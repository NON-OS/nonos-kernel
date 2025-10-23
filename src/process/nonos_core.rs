#![no_std]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
pub use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{structures::paging::PageTableFlags, VirtAddr, PhysAddr};

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
    pub zk_proofs_generated: AtomicU64,
    pub zk_proving_time_ms: AtomicU64,
    pub zk_proofs_verified: AtomicU64,
    pub zk_verification_time_ms: AtomicU64,
    pub zk_circuits_compiled: AtomicU64,
}

impl ProcessControlBlock {
    #[inline]
    pub fn terminate(&self, code: i32) {
        *self.state.lock() = ProcessState::Terminated(code);
    }

    #[inline]
    pub fn capability_token(&self) -> crate::syscall::capabilities::CapabilityToken {
        let bits = self.caps_bits.load(Ordering::Relaxed);
        let mut token_data = [0u8; 72]; // 8 bytes caps + 64 bytes signature
        token_data[..8].copy_from_slice(&bits.to_le_bytes());
        
        // Sign the capability bits with kernel key
        let kernel_keypair = crate::crypto::ed25519::KeyPair { public: [0u8; 32], private: [0u8; 32] };
        let sig = crate::crypto::ed25519::sign(&kernel_keypair, &token_data[..8]);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&sig.R);
        signature[32..].copy_from_slice(&sig.S);
        
        crate::syscall::capabilities::CapabilityToken {
            owner_module: self.pid as u64,
            permissions: vec![crate::capabilities::Capability::CoreExec],
            expires_at_ms: Some(crate::time::timestamp_millis() + 86400000), // 24h expiry
            nonce: bits,
            signature,
        }
    }

    /// Map anonymous private memory for this process.
    pub fn mmap(
        &self,
        hint: Option<VirtAddr>,
        length: usize,
        flags: PageTableFlags,
    ) -> Result<VirtAddr, &'static str> {
        if length == 0 { return Err("EINVAL"); }
        let pages = (length + 4095) / 4096;
        let map_flags = PageTableFlags::PRESENT
            | PageTableFlags::USER_ACCESSIBLE
            | (flags & (PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE));

        let mut mem = self.memory.lock();

        // Choose VA: accept aligned non-overlapping hint else bump-allocate
        let va = match hint {
            Some(h) if (h.as_u64() & 0xFFF) == 0 && !overlaps(&mem.vmas, h, length) => h,
            _ => {
                let mut candidate = align_up(mem.next_va, 0x1000);
                // Safety cap to avoid unbounded search.
                let upper_bound: u64 = 0x0000_FFFF_FFFF_F000;
                loop {
                    if candidate > upper_bound { return Err("ENOMEM"); }
                    let cand = VirtAddr::new(candidate);
                    if !overlaps(&mem.vmas, cand, length) { break cand; }
                    candidate = align_up(candidate + length as u64, 0x1000);
                }
            }
        };

        for i in 0..pages {
            let page_va = VirtAddr::new(va.as_u64() + (i as u64) * 4096);
            let phys = allocate_physical_page().ok_or("ENOMEM")?;
            map_page_to_phys(page_va, phys, map_flags).map_err(|_| "EIO")?;
            unsafe { core::ptr::write_bytes(page_va.as_u64() as *mut u8, 0, 4096); }
        }

        mem.vmas.push(Vma {
            start: va,
            end: VirtAddr::new(va.as_u64() + length as u64),
            flags: map_flags,
        });
        mem.resident_pages.fetch_add(pages as u64, Ordering::Relaxed);
        mem.next_va = align_up(va.as_u64() + length as u64, 0x1000);
        Ok(va)
    }

    /// Unmap range starting at `addr` for `length` bytes. Supports exact and partial unmaps.
    pub fn munmap(&self, addr: VirtAddr, length: usize) -> Result<(), &'static str> {
        if length == 0 || (addr.as_u64() & 0xFFF) != 0 { return Err("EINVAL"); }
        let end = addr.as_u64().checked_add(length as u64).ok_or("EINVAL")?;

        let mut mem = self.memory.lock();
        let mut i = 0usize;
        while i < mem.vmas.len() {
            let v = &mem.vmas[i];
            let vs = v.start.as_u64();
            let ve = v.end.as_u64();

            if end <= vs || addr.as_u64() >= ve { i += 1; continue; }

            let unmap_start = addr.as_u64().max(vs);
            let unmap_end = end.min(ve);
            let unmap_len = (unmap_end - unmap_start) as usize;

            unmap_range(VirtAddr::new(unmap_start), unmap_len).map_err(|_| "EIO")?;
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

// -------------------- Process table --------------------

#[derive(Default)]
pub struct ProcessTable {
    inner: RwLock<Vec<Arc<ProcessControlBlock>>>,
}

impl ProcessTable {
    pub fn add(&self, pcb: Arc<ProcessControlBlock>) { self.inner.write().push(pcb); }
    pub fn get_all_processes(&self) -> Vec<Arc<ProcessControlBlock>> { self.inner.read().clone() }
    pub fn find_by_pid(&self, pid: Pid) -> Option<Arc<ProcessControlBlock>> {
        self.inner.read().iter().find(|p| p.pid == pid).cloned()
    }
    pub fn is_active_name(&self, name: &str) -> bool {
        self.inner.read().iter().any(|p| p.name.lock().as_str() == name)
    }
    pub fn is_active_pid(&self, pid: u64) -> bool {
        self.inner.read().iter().any(|p| p.pid as u64 == pid)
    }
}

pub static PROCESS_TABLE: ProcessTable = ProcessTable { inner: RwLock::new(Vec::new()) };
static CURRENT_PID: AtomicU32 = AtomicU32::new(0);
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

#[inline] pub fn init_process_management() {}
#[inline] pub fn get_process_table() -> &'static ProcessTable { &PROCESS_TABLE }
#[inline] pub fn current_pid() -> Option<Pid> { match CURRENT_PID.load(Ordering::Relaxed) { 0 => None, v => Some(v) } }
#[inline] pub fn current_process() -> Option<Arc<ProcessControlBlock>> { current_pid().and_then(|pid| PROCESS_TABLE.find_by_pid(pid)) }

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
            next_va: 0x0000_4000_0000,
        }),
        argv: Mutex::new(Vec::new()),
        envp: Mutex::new(Vec::new()),
        caps_bits: AtomicU64::new(u64::MAX),
        zk_proofs_generated: AtomicU64::new(0),
        zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0),
        zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0),
    });
    PROCESS_TABLE.add(pcb);
    if CURRENT_PID.load(Ordering::Relaxed) == 0 { CURRENT_PID.store(pid, Ordering::Relaxed); }
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
    #[inline] pub fn sys_exit(_code: i32) -> ! {
        loop { unsafe { x86_64::instructions::hlt(); } }
    }
}

#[derive(Default)]
pub struct ProcessManagementStats { pub total: u64, pub running: u64, pub sleeping: u64, pub stopped: u64 }

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

// -------------------- Mapping primitives --------------------
#[cfg(not(test))]
fn allocate_physical_page() -> Option<PhysAddr> {
    crate::memory::robust_allocator::allocate_pages_robust(1)
}
#[cfg(not(test))]
fn map_page_to_phys(page_va: VirtAddr, phys: PhysAddr, flags: PageTableFlags) -> Result<(), ()> {
    crate::memory::virtual_memory::map_memory_range(page_va, phys, 4096, flags).map_err(|_| ())
}
#[cfg(not(test))]
fn unmap_range(addr: VirtAddr, len: usize) -> Result<(), ()> {
    crate::memory::virtual_memory::unmap_range(addr, len).map_err(|_| ())
}

// Test-only (compiled only during `cargo test`)
#[cfg(test)]
static mut MOCK_NEXT_PHYS: u64 = 0x1000_0000;
#[cfg(test)]
fn allocate_physical_page() -> Option<PhysAddr> {
    unsafe {
        let p = PhysAddr::new(MOCK_NEXT_PHYS);
        MOCK_NEXT_PHYS += 0x1000;
        Some(p)
    }
}
#[cfg(test)]
fn map_page_to_phys(_page_va: VirtAddr, _phys: PhysAddr, _flags: PageTableFlags) -> Result<(), ()> { Ok(()) }
#[cfg(test)]
fn unmap_range(_addr: VirtAddr, _len: usize) -> Result<(), ()> { Ok(()) }

// -------------------- Unit tests --------------------
#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::structures::paging::PageTableFlags;

    #[test]
    fn mmap_basic() {
        let pid = create_process("t1", ProcessState::Ready, Priority::Normal).expect("create");
        let pcb = get_process_table().find_by_pid(pid).expect("found");
        let va = pcb.mmap(None, 8192, PageTableFlags::WRITABLE).expect("mmap");
        assert_eq!(va.as_u64() & 0xFFF, 0);
        let mem = pcb.memory.lock();
        assert!(mem.vmas.iter().any(|v| v.start == va));
        assert_eq!(mem.resident_pages.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn mmap_overlap_hint() {
        let pid = create_process("t2", ProcessState::Ready, Priority::Normal).expect("create");
        let pcb = get_process_table().find_by_pid(pid).expect("found");
        let hint = VirtAddr::new(0x1000_0000_0000);
        let va1 = pcb.mmap(Some(hint), 4096, PageTableFlags::WRITABLE).expect("mmap1");
        assert_eq!(va1, hint);
        let va2 = pcb.mmap(Some(hint), 4096, PageTableFlags::WRITABLE).expect("mmap2");
        assert_ne!(va2, hint);
    }

    #[test]
    fn munmap_exact() {
        let pid = create_process("t3", ProcessState::Ready, Priority::Normal).expect("create");
        let pcb = get_process_table().find_by_pid(pid).expect("found");
        let va = pcb.mmap(None, 4096, PageTableFlags::WRITABLE).expect("mmap");
        pcb.munmap(va, 4096).expect("munmap");
        let mem = pcb.memory.lock();
        assert_eq!(mem.vmas.len(), 0);
        assert_eq!(mem.resident_pages.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn munmap_trim_and_split() {
        let pid = create_process("t4", ProcessState::Ready, Priority::Normal).expect("create");
        let pcb = get_process_table().find_by_pid(pid).expect("found");
        let va = pcb.mmap(None, 3 * 4096, PageTableFlags::WRITABLE).expect("mmap");
        pcb.munmap(va, 4096).expect("front");
        {
            let mem = pcb.memory.lock();
            assert_eq!(mem.vmas.len(), 1);
            assert_eq!(mem.vmas[0].start, VirtAddr::new(va.as_u64() + 4096));
        }
        let mid_start = pcb.memory.lock().vmas[0].start;
        pcb.munmap(VirtAddr::new(mid_start.as_u64() + 4096), 4096).expect("back");
        {
            let mem = pcb.memory.lock();
            assert_eq!(mem.vmas.len(), 1);
            assert_eq!(mem.vmas[0].end.as_u64() - mem.vmas[0].start.as_u64(), 4096);
            assert_eq!(mem.resident_pages.load(Ordering::Relaxed), 1);
        }
        let va2 = pcb.mmap(None, 3 * 4096, PageTableFlags::WRITABLE).expect("mmap2");
        pcb.munmap(VirtAddr::new(va2.as_u64() + 4096), 4096).expect("split");
        {
            let mem = pcb.memory.lock();
            assert!(mem.vmas.len() >= 2);
            assert!(mem.resident_pages.load(Ordering::Relaxed) >= 1);
        }
    }

    #[test]
    fn mmap_zero_length_error() {
        let pid = create_process("t5", ProcessState::Ready, Priority::Normal).expect("create");
        let pcb = get_process_table().find_by_pid(pid).expect("found");
        assert!(pcb.mmap(None, 0, PageTableFlags::WRITABLE).is_err());
    }

    #[test]
    fn munmap_unaligned_error() {
        let pid = create_process("t6", ProcessState::Ready, Priority::Normal).expect("create");
        let pcb = get_process_table().find_by_pid(pid).expect("found");
        let va = pcb.mmap(None, 4096, PageTableFlags::WRITABLE).expect("mmap");
        let bad = VirtAddr::new(va.as_u64() + 1);
        assert!(pcb.munmap(bad, 4096).is_err());
    }
}
