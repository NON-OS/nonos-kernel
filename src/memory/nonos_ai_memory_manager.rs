//! Memory Management System 

use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};
use x86_64::{VirtAddr, PhysAddr, structures::paging::PageTableFlags};

use crate::memory::virt::{self, VmFlags};
use crate::memory::nonos_alloc as alloc_api;

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
    pub prediction_accuracy: f32,
    pub prefetch_effectiveness: f32,
    pub security_incidents: u64,
    pub memory_saved: u64,
    pub performance_improvement: u64,
}

#[derive(Default)]
struct Counters {
    ai_allocations: AtomicU64,
    prediction_hits: AtomicU64,
    prediction_misses: AtomicU64,
    prefetch_hits: AtomicU64,
    prefetch_misses: AtomicU64,
    security_incidents: AtomicU64,
    memory_saved: AtomicU64,
    performance_improvement: AtomicU64,
}

pub struct AIMemoryManager {
    ctrs: Counters,
}

impl AIMemoryManager {
    pub fn new() -> Self { Self { ctrs: Counters::default() } }

    pub fn initialize(&mut self) -> Result<(), &'static str> {
        // No background threads; init is fast and deterministic
        Ok(())
    }

    // AI-guided memory allocation (now: policy-aware mapping with flags)
    pub fn ai_allocate(
        &mut self,
        size: usize,
        _alignment: usize,
        flags: PageTableFlags,
    ) -> Result<VirtAddr, &'static str> {
        let vmf = vmflags_from_pte(flags)?;
        let pages = ((size + crate::memory::layout::PAGE_SIZE - 1) / crate::memory::layout::PAGE_SIZE).max(1);
        let base = unsafe { alloc_api::kalloc_pages(pages, vmf) };
        if base.as_u64() == 0 { return Err("Out of memory"); }
        self.ctrs.ai_allocations.fetch_add(1, Ordering::SeqCst);
        Ok(base)
    }

    // Predictive prefetch (no-op placeholder; just bump misses for now)
    pub fn predictive_prefetch(&mut self, _current_access: VirtAddr) -> Result<(), &'static str> {
        self.ctrs.prefetch_misses.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // Security monitoring (no-op placeholder)
    pub fn monitor_memory_security(
        &mut self,
        _access: VirtAddr,
        _access_type: MemoryAccessType,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    pub fn get_ai_stats(&self) -> AIMemoryStatsSnapshot {
        let hits = self.ctrs.prediction_hits.load(Ordering::SeqCst) as f32;
        let misses = self.ctrs.prediction_misses.load(Ordering::SeqCst) as f32;
        let pa = if hits + misses > 0.0 { hits / (hits + misses) } else { 0.0 };

        let ph = self.ctrs.prefetch_hits.load(Ordering::SeqCst) as f32;
        let pm = self.ctrs.prefetch_misses.load(Ordering::SeqCst) as f32;
        let pe = if ph + pm > 0.0 { ph / (ph + pm) } else { 0.0 };

        AIMemoryStatsSnapshot {
            ai_allocations: self.ctrs.ai_allocations.load(Ordering::SeqCst),
            prediction_accuracy: pa,
            prefetch_effectiveness: pe,
            security_incidents: self.ctrs.security_incidents.load(Ordering::SeqCst),
            memory_saved: self.ctrs.memory_saved.load(Ordering::SeqCst),
            performance_improvement: self.ctrs.performance_improvement.load(Ordering::SeqCst),
        }
    }
}

// Global AI memory manager instance
static AI_MEMORY_MANAGER: Once<Mutex<AIMemoryManager>> = Once::new();

pub fn init_ai_memory_manager() -> Result<(), &'static str> {
    AI_MEMORY_MANAGER.call_once(|| Mutex::new(AIMemoryManager::new()));
    AI_MEMORY_MANAGER
        .get()
        .ok_or("AI manager not available")?
        .lock()
        .initialize()
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

pub fn ai_predictive_prefetch(_current_access: VirtAddr) -> Result<(), &'static str> {
    if let Some(manager) = get_ai_memory_manager() {
        manager.lock().predictive_prefetch(_current_access)
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

// Helpers

fn vmflags_from_pte(f: PageTableFlags) -> Result<VmFlags, &'static str> {
    // Enforce W^X: if WRITABLE set, force NX
    let mut vm = VmFlags::GLOBAL;
    if f.contains(PageTableFlags::WRITABLE) { vm |= VmFlags::RW | VmFlags::NX; }
    if f.contains(PageTableFlags::USER_ACCESSIBLE) { vm |= VmFlags::USER; }
    if f.contains(PageTableFlags::NO_EXECUTE) { vm |= VmFlags::NX; }
    if f.contains(PageTableFlags::PWT) { vm |= VmFlags::PWT; }
    if f.contains(PageTableFlags::PCD) { vm |= VmFlags::PCD; }
    Ok(vm)
}
