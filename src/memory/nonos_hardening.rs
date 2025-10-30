#![no_std]

use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use x86_64::{VirtAddr, PhysAddr};

use crate::memory::nonos_layout as layout;
use crate::memory::nonos_kaslr as kaslr;
use crate::memory::nonos_paging as paging;
use crate::memory::nonos_safety as safety;
use crate::memory::nonos_heap as heap;
use crate::memory::nonos_mmio as mmio;
use crate::memory::nonos_dma as dma;
use crate::memory::paging::PagePermissions;

pub static HARDENING_STATS: HardeningStats = HardeningStats::new();

pub struct HardeningStats {
    pub guard_page_violations: AtomicU64,
    pub wx_violations: AtomicU64,
    pub stack_overflows_detected: AtomicU64,
    pub heap_corruptions_detected: AtomicU64,
    pub double_frees_prevented: AtomicU64,
    pub use_after_free_detected: AtomicU64,
    pub mapped_file_pages: AtomicU64,
    pub total_mapped_size: AtomicU64,
    pub kernel_mappings: AtomicU64,
}

impl HardeningStats {
    pub const fn new() -> Self {
        Self {
            guard_page_violations: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
            stack_overflows_detected: AtomicU64::new(0),
            heap_corruptions_detected: AtomicU64::new(0),
            double_frees_prevented: AtomicU64::new(0),
            use_after_free_detected: AtomicU64::new(0),
            mapped_file_pages: AtomicU64::new(0),
            total_mapped_size: AtomicU64::new(0),
            kernel_mappings: AtomicU64::new(0),
        }
    }

    pub fn increment_guard_violations(&self) {
        self.guard_page_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_wx_violations(&self) {
        self.wx_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_stack_overflows(&self) {
        self.stack_overflows_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_heap_corruptions(&self) {
        self.heap_corruptions_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_double_frees(&self) {
        self.double_frees_prevented.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_use_after_free(&self) {
        self.use_after_free_detected.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GuardPage {
    pub addr: VirtAddr,
    pub size: usize,
    pub protection_type: GuardType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuardType {
    StackGuard,
    HeapGuard,
    KernelGuard,
    UserGuard,
}

#[derive(Debug)]
pub struct StackCanary {
    pub value: u64,
    pub stack_base: VirtAddr,
    pub stack_size: usize,
}

pub struct MemoryHardening {
    guard_pages: RwLock<BTreeMap<u64, GuardPage>>,
    stack_canaries: RwLock<BTreeMap<u64, StackCanary>>,
    allocation_tracker: Mutex<BTreeMap<u64, AllocationInfo>>,
    initialized: AtomicUsize,
}

#[derive(Debug, Clone)]
struct AllocationInfo {
    size: usize,
    timestamp: u64,
    allocation_id: u64,
    freed: bool,
}

static MEMORY_HARDENING: MemoryHardening = MemoryHardening::new();

impl MemoryHardening {
    const fn new() -> Self {
        Self {
            guard_pages: RwLock::new(BTreeMap::new()),
            stack_canaries: RwLock::new(BTreeMap::new()),
            allocation_tracker: Mutex::new(BTreeMap::new()),
            initialized: AtomicUsize::new(0),
        }
    }

    fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Ok(());
        }

        self.setup_kernel_guard_pages()?;
        self.setup_stack_protection()?;
        
        Ok(())
    }

    fn setup_kernel_guard_pages(&self) -> Result<(), &'static str> {
        let kernel_sections = layout::kernel_sections();
        let mut guards = self.guard_pages.write();

        for section in &kernel_sections {
            if section.rx && !section.rw {
                let guard_before = GuardPage {
                    addr: VirtAddr::new(section.start.saturating_sub(layout::PAGE_SIZE as u64)),
                    size: layout::PAGE_SIZE,
                    protection_type: GuardType::KernelGuard,
                };

                let guard_after = GuardPage {
                    addr: VirtAddr::new(section.end),
                    size: layout::PAGE_SIZE,
                    protection_type: GuardType::KernelGuard,
                };

                guards.insert(guard_before.addr.as_u64(), guard_before);
                guards.insert(guard_after.addr.as_u64(), guard_after);
            }
        }

        Ok(())
    }

    fn setup_stack_protection(&self) -> Result<(), &'static str> {
        let canary_value = self.generate_stack_canary();
        let stack_base = VirtAddr::new(layout::KHEAP_BASE - layout::KSTACK_SIZE as u64);
        
        let canary = StackCanary {
            value: canary_value,
            stack_base,
            stack_size: layout::KSTACK_SIZE,
        };

        self.stack_canaries.write().insert(stack_base.as_u64(), canary);

        let guard_page = GuardPage {
            addr: VirtAddr::new(stack_base.as_u64().saturating_sub(layout::PAGE_SIZE as u64)),
            size: layout::PAGE_SIZE,
            protection_type: GuardType::StackGuard,
        };

        self.guard_pages.write().insert(guard_page.addr.as_u64(), guard_page);

        Ok(())
    }

    fn generate_stack_canary(&self) -> u64 {
        let nonce = kaslr::boot_nonce().unwrap_or(0x1337DEADBEEF);
        let timestamp = unsafe { core::arch::x86_64::_rdtsc() };
        nonce.wrapping_mul(timestamp).wrapping_add(0x9e3779b97f4a7c15)
    }

    fn validate_wx_permissions(&self, addr: VirtAddr, writable: bool, executable: bool) -> Result<(), &'static str> {
        if writable && executable {
            HARDENING_STATS.increment_wx_violations();
            return Err("W^X violation: memory cannot be both writable and executable");
        }
        Ok(())
    }

    fn check_guard_page_violation(&self, addr: VirtAddr) -> bool {
        let guards = self.guard_pages.read();
        guards.contains_key(&addr.as_u64())
    }

    fn track_allocation(&self, addr: u64, size: usize) -> u64 {
        let allocation_id = self.generate_allocation_id();
        let timestamp = unsafe { core::arch::x86_64::_rdtsc() };
        
        let info = AllocationInfo {
            size,
            timestamp,
            allocation_id,
            freed: false,
        };

        self.allocation_tracker.lock().insert(addr, info);
        allocation_id
    }

    fn track_deallocation(&self, addr: u64) -> Result<(), &'static str> {
        let mut tracker = self.allocation_tracker.lock();
        
        match tracker.get_mut(&addr) {
            Some(info) if info.freed => {
                HARDENING_STATS.increment_double_frees();
                return Err("Double free detected");
            }
            Some(info) => {
                info.freed = true;
                Ok(())
            }
            None => {
                HARDENING_STATS.increment_use_after_free();
                Err("Use after free or invalid pointer")
            }
        }
    }

    fn generate_allocation_id(&self) -> u64 {
        static ALLOC_COUNTER: AtomicU64 = AtomicU64::new(1);
        ALLOC_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn check_stack_integrity(&self, stack_base: VirtAddr) -> Result<(), &'static str> {
        let canaries = self.stack_canaries.read();
        
        if let Some(canary) = canaries.get(&stack_base.as_u64()) {
            unsafe {
                let canary_location = (stack_base.as_u64() + canary.stack_size as u64 - 8) as *const u64;
                let current_canary = canary_location.read_volatile();
                
                if current_canary != canary.value {
                    HARDENING_STATS.increment_stack_overflows();
                    return Err("Stack overflow detected: canary corrupted");
                }
            }
        }

        Ok(())
    }

    fn detect_heap_corruption(&self, addr: u64, size: usize) -> Result<(), &'static str> {
        let pattern = 0xDEADBEEFCAFEBABE;
        
        unsafe {
            let ptr = addr as *const u64;
            for i in 0..(size / 8) {
                let value = ptr.add(i).read_volatile();
                if value == pattern || value == !pattern {
                    HARDENING_STATS.increment_heap_corruptions();
                    return Err("Heap corruption detected");
                }
            }
        }

        Ok(())
    }
}

pub fn init() -> Result<(), &'static str> {
    MEMORY_HARDENING.initialize()
}

pub fn validate_memory_permissions(addr: VirtAddr, writable: bool, executable: bool) -> Result<(), &'static str> {
    MEMORY_HARDENING.validate_wx_permissions(addr, writable, executable)
}

pub fn check_guard_page_access(addr: VirtAddr) -> bool {
    if MEMORY_HARDENING.check_guard_page_violation(addr) {
        HARDENING_STATS.increment_guard_violations();
        true
    } else {
        false
    }
}

pub fn track_allocation(addr: u64, size: usize) -> u64 {
    MEMORY_HARDENING.track_allocation(addr, size)
}

pub fn track_deallocation(addr: u64) -> Result<(), &'static str> {
    MEMORY_HARDENING.track_deallocation(addr)
}

pub fn check_stack_canary(stack_base: VirtAddr) -> Result<(), &'static str> {
    MEMORY_HARDENING.check_stack_integrity(stack_base)
}

pub fn validate_heap_integrity(addr: u64, size: usize) -> Result<(), &'static str> {
    MEMORY_HARDENING.detect_heap_corruption(addr, size)
}

pub fn add_guard_page(addr: VirtAddr, guard_type: GuardType) -> Result<(), &'static str> {
    let guard = GuardPage {
        addr,
        size: layout::PAGE_SIZE,
        protection_type: guard_type,
    };

    MEMORY_HARDENING.guard_pages.write().insert(addr.as_u64(), guard);
    Ok(())
}

pub fn remove_guard_page(addr: VirtAddr) -> Result<(), &'static str> {
    if MEMORY_HARDENING.guard_pages.write().remove(&addr.as_u64()).is_some() {
        Ok(())
    } else {
        Err("Guard page not found")
    }
}

pub fn get_hardening_stats() -> HardeningStatsSnapshot {
    HardeningStatsSnapshot {
        guard_violations: HARDENING_STATS.guard_page_violations.load(Ordering::Relaxed),
        wx_violations: HARDENING_STATS.wx_violations.load(Ordering::Relaxed),
        stack_overflows: HARDENING_STATS.stack_overflows_detected.load(Ordering::Relaxed),
        heap_corruptions: HARDENING_STATS.heap_corruptions_detected.load(Ordering::Relaxed),
        double_frees: HARDENING_STATS.double_frees_prevented.load(Ordering::Relaxed),
        use_after_free: HARDENING_STATS.use_after_free_detected.load(Ordering::Relaxed),
        total_guard_pages: MEMORY_HARDENING.guard_pages.read().len(),
        active_canaries: MEMORY_HARDENING.stack_canaries.read().len(),
        tracked_allocations: MEMORY_HARDENING.allocation_tracker.lock().len(),
    }
}

#[derive(Debug)]
pub struct HardeningStatsSnapshot {
    pub guard_violations: u64,
    pub wx_violations: u64,
    pub stack_overflows: u64,
    pub heap_corruptions: u64,
    pub double_frees: u64,
    pub use_after_free: u64,
    pub total_guard_pages: usize,
    pub active_canaries: usize,
    pub tracked_allocations: usize,
}

pub fn setup_stack_canary(stack_base: VirtAddr, stack_size: usize) -> Result<u64, &'static str> {
    let canary_value = MEMORY_HARDENING.generate_stack_canary();
    
    let canary = StackCanary {
        value: canary_value,
        stack_base,
        stack_size,
    };

    MEMORY_HARDENING.stack_canaries.write().insert(stack_base.as_u64(), canary);

    unsafe {
        let canary_location = (stack_base.as_u64() + stack_size as u64 - 8) as *mut u64;
        canary_location.write_volatile(canary_value);
    }

    Ok(canary_value)
}

pub fn clear_stack_canary(stack_base: VirtAddr) -> Result<(), &'static str> {
    if MEMORY_HARDENING.stack_canaries.write().remove(&stack_base.as_u64()).is_some() {
        Ok(())
    } else {
        Err("Stack canary not found")
    }
}

pub fn init_module_memory_protection() {
    paging::enable_write_protection();
    
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        
        if cr4 & (1 << 20) == 0 {
            cr4 |= 1 << 20;
        }
        
        if cr4 & (1 << 21) == 0 {
            cr4 |= 1 << 21;
        }
        
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
}

pub fn verify_kernel_data_integrity() -> bool {
    if layout::validate_layout().is_err() {
        return false;
    }
    
    let current_cr3 = paging::get_current_cr3();
    let current_cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) current_cr4, options(nostack, preserves_flags));
    }
    
    let required_cr4_bits = (1 << 20) | (1 << 21);
    if (current_cr4 & required_cr4_bits) != required_cr4_bits {
        return false;
    }
    
    if !verify_kernel_page_tables() {
        return false;
    }
    
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        let va = VirtAddr::new(section.start);
        
        if let Some(pa) = paging::translate_address(va) {
            if pa.as_u64() == 0 || pa.as_u64() > layout::MAX_PHYS_ADDR {
                return false;
            }
            
            if let Some(perms) = paging::get_page_permissions(va) {
                if section.rx && !perms.contains(PagePermissions::EXECUTE) {
                    return false;
                }
                if section.rw && !perms.contains(PagePermissions::WRITE) {
                    return false;
                }
                if !section.rw && perms.contains(PagePermissions::WRITE) {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    
    if !safety::verify_stack_integrity() {
        return false;
    }
    
    if !heap::verify_heap_integrity() {
        return false;
    }
    
    if !kaslr::verify_slide_integrity() {
        return false;
    }
    
    let kernel_entry_point = layout::KERNEL_BASE;
    if let Some(entry_pa) = paging::translate_address(VirtAddr::new(kernel_entry_point)) {
        if let Ok(entry_bytes) = read_bytes(kernel_entry_point as usize, 16) {
            if entry_bytes.iter().all(|&b| b == 0x90) {
                return false;
            }
            if entry_bytes.iter().all(|&b| b == 0x00) {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }
    
    true
}

pub fn verify_kernel_page_tables() -> bool {
    let current_cr3 = paging::get_current_cr3();
    
    let kernel_sections = layout::kernel_sections();
    
    for section in &kernel_sections {
        let va = VirtAddr::new(section.start);
        if let Some(perms) = paging::get_page_permissions(va) {
            if section.rx && !perms.contains(PagePermissions::EXECUTE) {
                return false;
            }
            if section.rw && !perms.contains(PagePermissions::WRITE) {
                return false;
            }
        } else {
            return false;
        }
    }
    
    true
}

pub fn get_all_process_regions() -> alloc::vec::Vec<(VirtAddr, usize)> {
    let mut regions = alloc::vec::Vec::new();
    
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        regions.push((VirtAddr::new(section.start), section.size() as usize));
    }
    
    if let Ok(heap_base) = layout::heap_base_for(0) {
        regions.push((VirtAddr::new(heap_base), layout::KHEAP_SIZE as usize));
    }
    
    let stack_regions = layout::get_all_stack_regions();
    for region in stack_regions {
        regions.push((VirtAddr::new(region.base), region.size));
    }
    
    let percpu_regions = layout::get_percpu_regions();
    for region in percpu_regions {
        regions.push((VirtAddr::new(region.base), region.size));
    }
    
    let mmio_regions = mmio::get_mapped_regions();
    for region in mmio_regions {
        regions.push((region.va, region.size));
    }
    
    let dma_regions = dma::get_allocated_regions();
    for region in dma_regions {
        regions.push((region.virt_addr, region.size));
    }
    
    let module_regions = layout::get_module_regions();
    for region in module_regions {
        regions.push((VirtAddr::new(region.base), region.size));
    }
    
    let guard_regions = safety::get_guard_regions();
    for region in guard_regions {
        regions.push((VirtAddr::new(region.start), (region.end - region.start) as usize));
    }
    
    regions.sort_by_key(|&(addr, _)| addr.as_u64());
    regions.dedup_by(|a, b| {
        let a_end = a.0.as_u64() + a.1 as u64;
        let b_start = b.0.as_u64();
        a_end > b_start && a.0.as_u64() <= b_start
    });
    
    regions
}

pub fn read_bytes(start: usize, size: usize) -> Result<&'static [u8], &'static str> {
    let va = VirtAddr::new(start as u64);
    
    if !paging::is_mapped(va) {
        return Err("Memory not mapped");
    }
    
    let end_va = VirtAddr::new((start + size) as u64);
    if !paging::is_mapped(end_va) {
        return Err("End of range not mapped");
    }
    
    unsafe {
        Ok(core::slice::from_raw_parts(start as *const u8, size))
    }
}