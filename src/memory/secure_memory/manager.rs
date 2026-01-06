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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::layout;
use crate::memory::buddy_alloc as mem_alloc;
use crate::memory::virt;
use super::constants::*;
use super::error::{SecureMemoryError, SecureMemoryResult};
use super::types::*;
static MEMORY_MANAGER: Mutex<MemoryManager> = Mutex::new(MemoryManager::new());
static MEMORY_STATS: MemoryStats = MemoryStats::new();
struct MemoryStats {
    total_allocated: AtomicU64,
    region_count: AtomicUsize,
    allocations: AtomicU64,
    deallocations: AtomicU64,
    peak_usage: AtomicU64,
}

impl MemoryStats {
    const fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            region_count: AtomicUsize::new(0),
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            peak_usage: AtomicU64::new(0),
        }
    }

    fn record_allocation(&self, size: u64) {
        let new_total = self.total_allocated.fetch_add(size, Ordering::AcqRel) + size;
        self.region_count.fetch_add(1, Ordering::Relaxed);
        self.allocations.fetch_add(1, Ordering::Relaxed);
        loop {
            let current_peak = self.peak_usage.load(Ordering::Relaxed);
            if new_total <= current_peak { break; }
            if self.peak_usage.compare_exchange_weak(current_peak, new_total, Ordering::AcqRel, Ordering::Relaxed).is_ok() { break; }
        }
    }

    fn record_deallocation(&self, size: u64) {
        self.total_allocated.fetch_sub(size, Ordering::AcqRel);
        self.region_count.fetch_sub(1, Ordering::Relaxed);
        self.deallocations.fetch_add(1, Ordering::Relaxed);
    }
}

struct MemoryManager {
    regions: BTreeMap<u64, MemoryRegion>,
    va_to_region: BTreeMap<u64, u64>,
    next_region_id: u64,
    initialized: bool,
}

impl MemoryManager {
    const fn new() -> Self {
        Self { regions: BTreeMap::new(), va_to_region: BTreeMap::new(), next_region_id: INITIAL_REGION_ID, initialized: false }
    }

    fn init(&mut self) -> SecureMemoryResult<()> {
        if self.initialized { return Ok(()); }
        self.regions.clear();
        self.va_to_region.clear();
        self.next_region_id = INITIAL_REGION_ID;
        self.initialized = true;
        Ok(())
    }

    fn allocate_region(&mut self, size: usize, region_type: RegionType, security_level: SecurityLevel, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
        if !self.initialized { return Err(SecureMemoryError::NotInitialized); }
        if size < MIN_ALLOCATION_SIZE || size > MAX_ALLOCATION_SIZE { return Err(SecureMemoryError::InvalidSize); }
        if self.regions.len() >= MAX_REGIONS { return Err(SecureMemoryError::RegionLimitExceeded); }
        let va = self.allocate_virtual_memory(size)?;
        let pa = self.get_physical_address(va)?;
        let region_id = self.next_region_id;
        self.next_region_id = self.next_region_id.wrapping_add(1);
        if self.next_region_id == INVALID_REGION_ID { self.next_region_id = INITIAL_REGION_ID; }
        let region = MemoryRegion::new(region_id, va, pa, size, region_type, security_level, owner_process, self.get_timestamp());
        self.regions.insert(region_id, region);
        self.va_to_region.insert(va.as_u64(), region_id);
        MEMORY_STATS.record_allocation(size as u64);
        Ok(va)
    }

    fn deallocate_region(&mut self, va: VirtAddr) -> SecureMemoryResult<()> {
        let region_id = self.va_to_region.remove(&va.as_u64()).ok_or(SecureMemoryError::AddressNotFound)?;
        let region = self.regions.remove(&region_id).ok_or(SecureMemoryError::RegionNotFound)?;
        self.secure_zero_memory(va, region.size, region.security_level)?;
        self.free_virtual_memory(va, region.size)?;
        MEMORY_STATS.record_deallocation(region.size as u64);
        Ok(())
    }

    fn get_region_info(&self, va: VirtAddr) -> Option<&MemoryRegion> {
        self.va_to_region.get(&va.as_u64()).and_then(|id| self.regions.get(id))
    }

    fn validate_access(&self, process_id: u64, va: VirtAddr, write: bool) -> bool {
        if let Some(region) = self.get_region_info(va) {
            if region.owner_process != process_id && region.owner_process != KERNEL_PROCESS_ID { return false; }
            match region.region_type {
                RegionType::Code => !write,
                RegionType::Data | RegionType::Stack | RegionType::Heap | RegionType::Device => true,
                RegionType::Capsule => region.security_level >= SecurityLevel::Confidential,
            }
        } else { false }
    }

    fn allocate_virtual_memory(&self, size: usize) -> SecureMemoryResult<VirtAddr> {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        mem_alloc::allocate_pages(page_count).map_err(|_| SecureMemoryError::AllocationFailed)
    }

    fn free_virtual_memory(&self, va: VirtAddr, size: usize) -> SecureMemoryResult<()> {
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        mem_alloc::free_pages(va, page_count).map_err(|_| SecureMemoryError::AllocationFailed)
    }

    fn get_physical_address(&self, va: VirtAddr) -> SecureMemoryResult<PhysAddr> {
        virt::translate_addr(va).map_err(|_| SecureMemoryError::TranslationFailed)
    }

    fn secure_zero_memory(&self, va: VirtAddr, size: usize, security_level: SecurityLevel) -> SecureMemoryResult<()> {
        let passes = security_level.scrub_passes();
        if passes == 0 {
            // SAFETY: We own this memory region
            unsafe { core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size); }
        } else {
            for pass in 0..passes {
                let pattern = if pass % 2 == 0 { SECURE_SCRUB_PATTERN } else { !SECURE_SCRUB_PATTERN };
                // SAFETY: We own this memory, alternating pattern for thorough clearing
                unsafe { core::ptr::write_bytes(va.as_mut_ptr::<u8>(), pattern, size); }
                core::sync::atomic::compiler_fence(Ordering::SeqCst);
            }
            // SAFETY: Final zero pass
            unsafe { core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size); }
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
        }
        Ok(())
    }

    fn get_timestamp(&self) -> u64 {
        // SAFETY: _rdtsc has no side effects
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn get_stats(&self) -> ManagerStats {
        ManagerStats {
            total_regions: self.regions.len(),
            allocated_memory: MEMORY_STATS.total_allocated.load(Ordering::Relaxed),
            peak_memory: MEMORY_STATS.peak_usage.load(Ordering::Relaxed),
            allocations: MEMORY_STATS.allocations.load(Ordering::Relaxed),
            deallocations: MEMORY_STATS.deallocations.load(Ordering::Relaxed),
        }
    }
}

// Public API
pub fn init() -> SecureMemoryResult<()> { MEMORY_MANAGER.lock().init() }
pub fn allocate_memory(size: usize, region_type: RegionType, security_level: SecurityLevel, owner_process: u64) -> SecureMemoryResult<VirtAddr> {
    MEMORY_MANAGER.lock().allocate_region(size, region_type, security_level, owner_process)
}

pub fn deallocate_memory(va: VirtAddr) -> SecureMemoryResult<()> { MEMORY_MANAGER.lock().deallocate_region(va) }
pub fn get_region_info(va: VirtAddr) -> Option<MemoryRegion> { MEMORY_MANAGER.lock().get_region_info(va).copied() }
pub fn validate_memory_access(process_id: u64, va: VirtAddr, write: bool) -> bool { MEMORY_MANAGER.lock().validate_access(process_id, va, write) }
pub fn allocate_code_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> { allocate_memory(size, RegionType::Code, SecurityLevel::Public, owner_process) }
pub fn allocate_data_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> { allocate_memory(size, RegionType::Data, SecurityLevel::Internal, owner_process) }
pub fn allocate_heap_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> { allocate_memory(size, RegionType::Heap, SecurityLevel::Internal, owner_process) }
pub fn allocate_stack_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> { allocate_memory(size, RegionType::Stack, SecurityLevel::Internal, owner_process) }
pub fn allocate_secure_capsule(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> { allocate_memory(size, RegionType::Capsule, SecurityLevel::Secret, owner_process) }
pub fn allocate_device_region(size: usize, owner_process: u64) -> SecureMemoryResult<VirtAddr> { allocate_memory(size, RegionType::Device, SecurityLevel::Public, owner_process) }
pub fn zero_memory(va: VirtAddr, size: usize) -> SecureMemoryResult<()> {
    if size == 0 { return Ok(()); }
    // SAFETY: Caller guarantees valid memory
    unsafe { core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size); }
    Ok(())
}

pub fn copy_memory(src: VirtAddr, dst: VirtAddr, size: usize) -> SecureMemoryResult<()> {
    if size == 0 { return Ok(()); }
    // SAFETY: Caller guarantees valid non-overlapping memory
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr::<u8>(), dst.as_mut_ptr::<u8>(), size); }
    Ok(())
}

pub fn get_memory_stats() -> ManagerStats { MEMORY_MANAGER.lock().get_stats() }
#[inline] pub fn get_total_memory() -> u64 { MEMORY_STATS.total_allocated.load(Ordering::Relaxed) }
#[inline] pub fn get_peak_memory() -> u64 { MEMORY_STATS.peak_usage.load(Ordering::Relaxed) }
#[inline] pub fn get_allocation_count() -> u64 { MEMORY_STATS.allocations.load(Ordering::Relaxed) }
#[inline] pub fn get_deallocation_count() -> u64 { MEMORY_STATS.deallocations.load(Ordering::Relaxed) }
#[inline] pub fn get_region_count() -> usize { MEMORY_STATS.region_count.load(Ordering::Relaxed) }
pub fn is_valid_address(va: VirtAddr) -> bool { MEMORY_MANAGER.lock().get_region_info(va).is_some() }
pub fn is_initialized() -> bool { MEMORY_MANAGER.lock().initialized }
