// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use x86_64::VirtAddr;
use crate::memory::paging::PagePermissions;
use crate::memory::{dma, heap, kaslr, layout, mmio, paging, safety};
use super::constants::*;
use super::stats::HardeningStats;
use super::types::*;
pub static HARDENING_STATS: HardeningStats = HardeningStats::new();
static MEMORY_HARDENING: MemoryHardening = MemoryHardening::new();
struct MemoryHardening {
    guard_pages: RwLock<BTreeMap<u64, GuardPage>>,
    stack_canaries: RwLock<BTreeMap<u64, StackCanary>>,
    allocation_tracker: Mutex<BTreeMap<u64, AllocationInfo>>,
    initialized: AtomicUsize,
}

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
        let canary = StackCanary { value: canary_value, stack_base, stack_size: layout::KSTACK_SIZE };
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
        // SAFETY: rdtsc is always safe on x86_64
        let timestamp = unsafe { core::arch::x86_64::_rdtsc() };
        nonce.wrapping_mul(timestamp).wrapping_add(CANARY_MIX_CONSTANT)
    }

    fn validate_wx_permissions(&self, _addr: VirtAddr, writable: bool, executable: bool) -> Result<(), &'static str> {
        if writable && executable {
            HARDENING_STATS.increment_wx_violations();
            return Err("W^X violation: memory cannot be both writable and executable");
        }
        Ok(())
    }

    fn check_guard_page_violation(&self, addr: VirtAddr) -> bool {
        self.guard_pages.read().contains_key(&addr.as_u64())
    }

    fn track_allocation(&self, addr: u64, size: usize) -> u64 {
        let allocation_id = self.generate_allocation_id();
        // SAFETY: rdtsc is always safe on x86_64
        let timestamp = unsafe { core::arch::x86_64::_rdtsc() };
        let info = AllocationInfo { size, timestamp, allocation_id, freed: false };
        self.allocation_tracker.lock().insert(addr, info);
        allocation_id
    }

    fn track_deallocation(&self, addr: u64) -> Result<(), &'static str> {
        let mut tracker = self.allocation_tracker.lock();
        match tracker.get_mut(&addr) {
            Some(info) if info.freed => {
                HARDENING_STATS.increment_double_frees();
                Err("Double free detected")
            }
            Some(info) => { info.freed = true; Ok(()) }
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
            // SAFETY: Reading canary at known location within valid stack region
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
        // SAFETY: Reading memory at provided address to check for corruption patterns
        unsafe {
            let ptr = addr as *const u64;
            for i in 0..(size / 8) {
                let value = ptr.add(i).read_volatile();
                if value == CORRUPTION_PATTERN || value == !CORRUPTION_PATTERN {
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
    let guard = GuardPage { addr, size: layout::PAGE_SIZE, protection_type: guard_type };
    MEMORY_HARDENING.guard_pages.write().insert(addr.as_u64(), guard);
    Ok(())
}

pub fn remove_guard_page(addr: VirtAddr) -> Result<(), &'static str> {
    if MEMORY_HARDENING.guard_pages.write().remove(&addr.as_u64()).is_some() { Ok(()) }
    else { Err("Guard page not found") }
}

pub fn get_hardening_stats() -> HardeningStatsSnapshot {
    HardeningStatsSnapshot {
        guard_violations: HARDENING_STATS.guard_violations(),
        wx_violations: HARDENING_STATS.wx_violations(),
        stack_overflows: HARDENING_STATS.stack_overflows(),
        heap_corruptions: HARDENING_STATS.heap_corruptions(),
        double_frees: HARDENING_STATS.double_frees(),
        use_after_free: HARDENING_STATS.use_after_free(),
        total_guard_pages: MEMORY_HARDENING.guard_pages.read().len(),
        active_canaries: MEMORY_HARDENING.stack_canaries.read().len(),
        tracked_allocations: MEMORY_HARDENING.allocation_tracker.lock().len(),
    }
}

pub fn setup_stack_canary(stack_base: VirtAddr, stack_size: usize) -> Result<u64, &'static str> {
    let canary_value = MEMORY_HARDENING.generate_stack_canary();
    let canary = StackCanary { value: canary_value, stack_base, stack_size };
    MEMORY_HARDENING.stack_canaries.write().insert(stack_base.as_u64(), canary);

    // SAFETY: Writing canary value at end of valid stack region
    unsafe {
        let canary_location = (stack_base.as_u64() + stack_size as u64 - 8) as *mut u64;
        canary_location.write_volatile(canary_value);
    }
    Ok(canary_value)
}

pub fn clear_stack_canary(stack_base: VirtAddr) -> Result<(), &'static str> {
    if MEMORY_HARDENING.stack_canaries.write().remove(&stack_base.as_u64()).is_some() { Ok(()) }
    else { Err("Stack canary not found") }
}

pub fn init_module_memory_protection() {
    paging::enable_write_protection();

    // SAFETY: Reading and writing CR4 is safe in ring 0
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        if cr4 & CR4_SMEP == 0 { cr4 |= CR4_SMEP; }
        if cr4 & CR4_SMAP == 0 { cr4 |= CR4_SMAP; }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
}

pub fn verify_kernel_data_integrity() -> bool {
    if layout::validate_layout().is_err() { return false; }

    let _current_cr3 = paging::get_current_cr3();

    // SAFETY: Reading CR4 is safe
    let current_cr4: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) current_cr4, options(nostack, preserves_flags)); }

    if (current_cr4 & CR4_REQUIRED_BITS) != CR4_REQUIRED_BITS { return false; }
    if !verify_kernel_page_tables() { return false; }

    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        let va = VirtAddr::new(section.start);
        if let Some(pa) = paging::translate_address(va) {
            if pa.as_u64() == 0 || pa.as_u64() > layout::MAX_PHYS_ADDR { return false; }
            if let Some(perms) = paging::get_page_permissions(va) {
                if section.rx && !perms.contains(PagePermissions::EXECUTE) { return false; }
                if section.rw && !perms.contains(PagePermissions::WRITE) { return false; }
                if !section.rw && perms.contains(PagePermissions::WRITE) { return false; }
            } else { return false; }
        } else { return false; }
    }

    if !safety::verify_stack_integrity() { return false; }
    if !heap::verify_heap_integrity() { return false; }
    if !kaslr::verify_slide_integrity() { return false; }
    let kernel_entry_point = layout::KERNEL_BASE;
    if paging::translate_address(VirtAddr::new(kernel_entry_point)).is_some() {
        if let Ok(entry_bytes) = read_bytes(kernel_entry_point as usize, NOP_SLED_CHECK_SIZE) {
            if entry_bytes.iter().all(|&b| b == NOP_INSTRUCTION) { return false; }
            if entry_bytes.iter().all(|&b| b == 0x00) { return false; }
        } else { return false; }
    } else { return false; }

    true
}

pub fn verify_kernel_page_tables() -> bool {
    let _current_cr3 = paging::get_current_cr3();
    let kernel_sections = layout::kernel_sections();
    for section in &kernel_sections {
        let va = VirtAddr::new(section.start);
        if let Some(perms) = paging::get_page_permissions(va) {
            if section.rx && !perms.contains(PagePermissions::EXECUTE) { return false; }
            if section.rw && !perms.contains(PagePermissions::WRITE) { return false; }
        } else { return false; }
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

    for region in layout::get_all_stack_regions() {
        regions.push((VirtAddr::new(region.base), region.size));
    }

    for region in layout::get_percpu_regions() {
        regions.push((VirtAddr::new(region.base), region.size));
    }

    for region in mmio::get_mapped_regions() {
        regions.push((region.va, region.size));
    }

    for region in dma::get_allocated_regions() {
        regions.push((region.virt_addr, region.size));
    }

    for region in layout::get_module_regions() {
        regions.push((VirtAddr::new(region.base), region.size));
    }

    for region in safety::get_guard_regions() {
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
    if !paging::is_mapped(va) { return Err("Memory not mapped"); }
    let end_va = VirtAddr::new((start + size) as u64);
    if !paging::is_mapped(end_va) { return Err("End of range not mapped"); }

    // SAFETY: We've verified the memory range is mapped
    unsafe { Ok(core::slice::from_raw_parts(start as *const u8, size)) }
}
