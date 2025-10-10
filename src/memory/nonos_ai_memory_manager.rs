//! AI Memory Management System

use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};
use x86_64::{VirtAddr, structures::paging::PageTableFlags};

use crate::memory::layout::PAGE_SIZE;
use crate::memory::nonos_alloc as alloc_api;
use crate::memory::virt::{self, VmFlags};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryAccessType {
    Read,
    Write,
    Execute,
    Prefetch,
}

#[derive(Debug, Clone)]
pub struct AIMemoryStatsSnapshot {
    pub ai_allocations: u64,
    pub w_x_violations: u64,
    pub prefetch_attempts: u64,
    pub prefetch_hits: u64,
    pub prefetch_misses: u64,
}

#[derive(Default)]
struct Counters {
    ai_allocations: AtomicU64,
    wx_violations: AtomicU64,
    prefetch_attempts: AtomicU64,
    prefetch_hits: AtomicU64,
    prefetch_misses: AtomicU64,
}

pub struct AIMemoryManager {
    ctrs: Counters,
}

impl AIMemoryManager {
    pub fn new() -> Self { Self { ctrs: Counters::default() } }

    pub fn initialize(&mut self) -> Result<(), &'static str> { Ok(()) }

    // Real allocation via nonos_alloc with enforced W^X
    pub fn ai_allocate(
        &mut self,
        size: usize,
        _alignment: usize,
        flags: PageTableFlags,
    ) -> Result<VirtAddr, &'static str> {
        let vmf = vmflags_from_pte(flags)?;
        let pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
        let base = unsafe { alloc_api::kalloc_pages(pages, vmf) };
        if base.as_u64() == 0 { return Err("Out of memory"); }
        self.ctrs.ai_allocations.fetch_add(1, Ordering::SeqCst);
        Ok(base)
    }

    // Real prefetch: pre-touch the next page (if mapped) to warm TLB/cache.
    pub fn predictive_prefetch(&mut self, current_access: VirtAddr) -> Result<(), &'static str> {
        self.ctrs.prefetch_attempts.fetch_add(1, Ordering::Relaxed);

        let page_base = VirtAddr::new(current_access.as_u64() & !((PAGE_SIZE as u64) - 1));
        let next_page = VirtAddr::new(page_base.as_u64() + PAGE_SIZE as u64);

        match virt::translate(next_page) {
            Ok((_pa, _f, _sz)) => {
                unsafe { core::ptr::read_volatile(next_page.as_ptr::<u8>()); }
                self.ctrs.prefetch_hits.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.ctrs.prefetch_misses.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    // Real security check: detect RW+X, remediate to RW+NX by default.
    pub fn monitor_memory_security(
        &mut self,
        access: VirtAddr,
        _access_type: MemoryAccessType,
    ) -> Result<(), &'static str> {
        let (_pa, flags, _sz) = virt::translate(access).map_err(|_| "not mapped")?;
        let is_writable = flags.contains(VmFlags::RW);
        let is_executable = !flags.contains(VmFlags::NX);

        if is_writable && is_executable {
            self.ctrs.wx_violations.fetch_add(1, Ordering::SeqCst);
            let page = VirtAddr::new(access.as_u64() & !((PAGE_SIZE as u64) - 1));
            crate::memory::virt::protect_range_4k(page, PAGE_SIZE, (flags | VmFlags::NX) & !VmFlags::RW)
                .map_err(|_| "protect failed")?;
            crate::memory::proof::audit_protect(page.as_u64(), PAGE_SIZE as u64, (flags | VmFlags::NX).bits(), crate::memory::proof::CapTag::KERNEL);
        }
        Ok(())
    }

    pub fn get_ai_stats(&self) -> AIMemoryStatsSnapshot {
        AIMemoryStatsSnapshot {
            ai_allocations: self.ctrs.ai_allocations.load(Ordering::SeqCst),
            w_x_violations: self.ctrs.wx_violations.load(Ordering::SeqCst),
            prefetch_attempts: self.ctrs.prefetch_attempts.load(Ordering::SeqCst),
            prefetch_hits: self.ctrs.prefetch_hits.load(Ordering::SeqCst),
            prefetch_misses: self.ctrs.prefetch_misses.load(Ordering::SeqCst),
        }
    }
}

// Global instance
static AI_MEMORY_MANAGER: Once<Mutex<AIMemoryManager>> = Once::new();

pub fn init_ai_memory_manager() -> Result<(), &'static str> {
    AI_MEMORY_MANAGER.call_once(|| Mutex::new(AIMemoryManager::new()));
    AI_MEMORY_MANAGER.get().ok_or("AI manager not available")?.lock().initialize()
}

pub fn get_ai_memory_manager() -> Option<&'static Mutex<AIMemoryManager>> {
    AI_MEMORY_MANAGER.get()
}

pub fn ai_allocate_memory(size: usize, alignment: usize, flags: PageTableFlags) -> Result<VirtAddr, &'static str> {
    if let Some(manager) = get_ai_memory_manager() {
        manager.lock().ai_allocate(size, alignment, flags)
    } else {
        Err("AI manager not initialized")
    }
}

pub fn ai_predictive_prefetch(current_access: VirtAddr) -> Result<(), &'static str> {
    if let Some(manager) = get_ai_memory_manager() {
        manager.lock().predictive_prefetch(current_access)
    } else {
        Ok(())
    }
}

pub fn ai_monitor_memory_access(access: VirtAddr, access_type: MemoryAccessType) -> Result<(), &'static str> {
    if let Some(manager) = get_ai_memory_manager() {
        manager.lock().monitor_memory_security(access, access_type)
    } else {
        Ok(())
    }
}

pub fn get_ai_memory_stats() -> Option<AIMemoryStatsSnapshot> {
    get_ai_memory_manager().map(|m| m.lock().get_ai_stats())
}

// Helpers: enforce W^X when converting PageTableFlags → VmFlags
fn vmflags_from_pte(f: PageTableFlags) -> Result<VmFlags, &'static str> {
    let mut vm = VmFlags::GLOBAL;
    if f.contains(PageTableFlags::WRITABLE) { vm |= VmFlags::RW | VmFlags::NX; }
    if f.contains(PageTableFlags::USER_ACCESSIBLE) { vm |= VmFlags::USER; }
    if f.contains(PageTableFlags::NO_EXECUTE) { vm |= VmFlags::NX; }
    if f.contains(PageTableFlags::PWT) { vm |= VmFlags::PWT; }
    if f.contains(PageTableFlags::PCD) { vm |= VmFlags::PCD; }
    Ok(vm)
}
