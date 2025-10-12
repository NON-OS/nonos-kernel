#![no_std]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

pub type Pid = u32;
pub type Tid = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    New,
    Ready,
    Running,
    Sleeping,
    Stopped,
    Zombie(i32),
    Terminated(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Idle,
    Low,
    Normal,
    High,
    RealTime,
}

#[derive(Debug, Clone)]
pub struct Vma {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub flags: PageTableFlags,
}

#[derive(Debug)]
pub struct MemoryState {
    pub code_start: VirtAddr,
    pub code_end: VirtAddr,
    pub vmas: Vec<Vma>,
    pub resident_pages: AtomicU64,
    next_va: u64,
}

#[derive(Debug)]
pub struct ProcessControlBlock {
    pub pid: Pid,
    pub name: Mutex<String>,
    pub state: Mutex<ProcessState>,
    pub priority: Mutex<Priority>,
    pub memory: Mutex<MemoryState>,
    pub argv: Mutex<Vec<String>>,
    pub envp: Mutex<Vec<String>>,
    pub caps_bits: AtomicU64,
}

impl ProcessControlBlock {
    #[inline]
    pub fn terminate(&self, code: i32) {
        *self.state.lock() = ProcessState::Terminated(code);
    }

    // Anonymous private mappings with overlap avoidance and zeroing
    pub fn mmap(
        &self,
        hint: Option<VirtAddr>,
        length: usize,
        flags: PageTableFlags,
    ) -> Result<VirtAddr, &'static str> {
        if length == 0 { return Err("EINVAL"); }
        let pages = (length + 4095) / 4096;
        let map_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
            | (flags & (PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE));
        let mut mem = self.memory.lock();

        // Choose VA: non-overlapping hint else bump-allocate
        let va = match hint {
            Some(h) if (h.as_u64() & 0xFFF) == 0 && !overlaps(&mem.vmas, h, length) => h,
            _ => {
                let mut candidate = align_up(mem.next_va, 0x1000);
                loop {
                    let cand = VirtAddr::new(candidate);
                    if !overlaps(&mem.vmas, cand, length) { break cand; }
                    candidate = align_up(candidate + length as u64, 0x1000);
                }
            }
        };

        // Map and zero pages
        for i in 0..pages {
            let page_va = VirtAddr::new(va.as_u64() + (i as u64) * 4096);
            let phys = crate::memory::robust_allocator::allocate_pages_robust(1).ok_or("ENOMEM")?;
            crate::memory::virtual_memory::map_memory_range(page_va, phys, 4096, map_flags)?;
            unsafe { core::ptr::write_bytes(page_va.as_u64() as *mut u8, 0, 4096); }
        }

        mem.vmas.push(Vma { start: va, end: VirtAddr::new(va.as_u64() + length as u64), flags: map_flags });
        mem.resident_pages.fetch_add(pages as u64, Ordering::Relaxed);
        mem.next_va = align_up(va.as_u64() + length as u64, 0x1000);
        Ok(va)
    }

    // Partial and exact munmap with VMA split/trim and accounting
    pub fn munmap(&self, addr: VirtAddr, length: usize) -> Result<(), &'static str> {
        if length == 0 || (addr.as_u64() & 0xFFF) != 0 { return Err("EINVAL"); }
        let end = addr.as_u64().checked_add(length as u64).ok_or("EINVAL")?;

        let mut mem = self.memory.lock();
        let mut i = 0;
        while i < mem.vmas.len() {
            let v = &mem.vmas[i];
            let vs = v.start.as_u64();
            let ve = v.end.as_u64();

            if end <= vs || addr.as_u64() >= ve {
                i += 1;
                continue;
            }

            let unmap_start = addr.as_u64().max(vs);
            let unmap_end = end.min(ve);
            let unmap_len = (unmap_end - unmap_start) as usize;

            crate::memory::virtual_memory::unmap_range(VirtAddr::new(unmap_start), unmap_len)?;
            mem.resident_pages.fetch_sub(((unmap_len + 4095) / 4096) as u64, Ordering::Relaxed);

            if unmap_start == vs && unmap_end == ve {
                mem.vmas.swap_remove(i);
                continue;
            } else if unmap_start == vs {
                mem.vmas[i].start = VirtAddr::new(unmap_end);
                i += 1;
            } else if unmap_end == ve {
                mem.vmas[i].end = VirtAddr::new(unmap_start);
                i += 1;
            } else {
                let right = Vma { start: VirtAddr::new(unmap_end), end: v.end, flags: v.flags };
                mem.vmas[i].end = VirtAddr::new(unmap_start);
                mem.vmas.push(right);
                i += 1;
            }
        }

        Ok(())
    }
}

#[inline] fn align_up(v: u64, a: u64) -> u64 { (v + (a - 1)) & !(a - 1) }

#[inline]
fn overlaps(vmas: &[Vma], start: VirtAddr, len: usize) -> bool {
    let s = start.as_u64();
    let e = s + len as u64;
    for v in vmas {
        let vs = v.start.as_u64();
        let ve = v.end.as_u64();
        if !(e <= vs || s >= ve) { return true; }
    }
    false
}

#[derive(Default)]
pub struct ProcessTable {
    inner: RwLock<Vec<Arc<ProcessControlBlock>>>,
}

impl ProcessTable {
    pub fn add(&self, pcb: Arc<ProcessControlBlock>) { self.inner.write().push(pcb); }
    pub fn get_all_processes(&self) -> Vec<Arc<ProcessControlBlock>> { self.inner.read().clone() }
    pub fn find_by_pid(&self, pid: Pid) -> Option<Arc<ProcessControlBlock>> { self.inner.read().iter().find(|p| p.pid == pid).cloned() }
    pub fn is_active_name(&self, name: &str) -> bool { self.inner.read().iter().any(|p| p.name.lock().as_str() == name) }
    pub fn is_active_pid(&self, pid: u64) -> bool { self.inner.read().iter().any(|p| p.pid as u64 == pid) }
}

static PROCESS_TABLE: ProcessTable = ProcessTable { inner: RwLock::new(Vec::new()) };
static CURRENT_PID: AtomicU32 = AtomicU32::new(0);
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

#[inline] pub fn init_process_management() {}
#[inline] pub fn get_process_table() -> &'static ProcessTable { &PROCESS_TABLE }

#[inline]
pub fn current_pid() -> Option<Pid> {
    match CURRENT_PID.load(Ordering::Relaxed) { 0 => None, v => Some(v) }
}

#[inline]
pub fn current_process() -> Option<Arc<ProcessControlBlock>> {
    current_pid().and_then(|pid| PROCESS_TABLE.find_by_pid(pid))
}

pub fn create_process(name: &str, state: ProcessState, prio: Priority) -> Result<Pid, &'static str> {
    if name.is_empty() { return Err("empty name"); }
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let pcb = Arc::new(ProcessControlBlock {
        pid,
        name: Mutex::new(String::from(name)),
        state: Mutex::new(state),
        priority: Mutex::new(prio),
        memory: Mutex::new(MemoryState {
            code_start: VirtAddr::new(0),
            code_end: VirtAddr::new(0),
            vmas: Vec::new(),
            resident_pages: AtomicU64::new(0),
            next_va: 0x0000_4000_0000, // user VA base for anon mmaps
        }),
        argv: Mutex::new(Vec::new()),
        envp: Mutex::new(Vec::new()),
        caps_bits: AtomicU64::new(u64::MAX), // policy can tighten
    });
    PROCESS_TABLE.add(pcb);
    if CURRENT_PID.load(Ordering::Relaxed) == 0 {
        CURRENT_PID.store(pid, Ordering::Relaxed);
    }
    Ok(pid)
}

#[inline] pub fn context_switch(to: Pid) -> Result<(), &'static str> {
    if PROCESS_TABLE.find_by_pid(to).is_none() { return Err("not found"); }
    CURRENT_PID.store(to, Ordering::Relaxed);
    Ok(())
}

#[inline] pub fn is_process_active(name: &str) -> bool { PROCESS_TABLE.is_active_name(name) }
#[inline] pub fn is_process_active_by_id(pid: u64) -> bool { PROCESS_TABLE.is_active_pid(pid) }

pub mod syscalls {
    #[inline] pub fn sys_exit(_code: i32) -> ! { loop { unsafe { x86_64::instructions::hlt(); } } }
}

#[derive(Default)]
pub struct ProcessManagementStats {
    pub total: u64,
    pub running: u64,
    pub sleeping: u64,
    pub stopped: u64,
}

pub fn get_process_stats() -> ProcessManagementStats {
    let mut stats = ProcessManagementStats::default();
    let list = super::nonos_core::get_process_table().get_all_processes();
    stats.total = list.len() as u64;
    for p in list {
        match *p.state.lock() {
            ProcessState::Running => stats.running += 1,
            ProcessState::Sleeping => stats.sleeping += 1,
            ProcessState::Stopped => stats.stopped += 1,
            _ => {}
        }
    }
    stats
}

pub fn isolate_process(_pid: Pid) -> Result<(), &'static str> { Ok(()) }
pub fn suspend_process(_pid: Pid) -> Result<(), &'static str> { Ok(()) }
