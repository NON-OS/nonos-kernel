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
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::PhysAddr;
use super::constants::*;
use super::error::{BootMemoryError, BootMemoryResult};
use super::types::*;

static BOOT_MEMORY_MANAGER: Mutex<Option<BootMemoryManager>> = Mutex::new(None);
static TOTAL_MEMORY: AtomicU64 = AtomicU64::new(0);
static AVAILABLE_MEMORY: AtomicU64 = AtomicU64::new(0);
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct BootMemoryManager {
    regions: Vec<MemoryRegion>,
    next_free: PhysAddr,
    total_size: u64,
    allocated_size: u64,
    initialized: bool,
}

impl BootMemoryManager {
    const fn new() -> Self {
        Self { regions: Vec::new(), next_free: PhysAddr::new(0), total_size: 0, allocated_size: 0, initialized: false }
    }

    fn init_from_handoff(&mut self, handoff_addr: u64) -> BootMemoryResult<()> {
        if handoff_addr == 0 { return self.init_default(); }

        // SAFETY: Bootloader places handoff at known-good location
        let handoff = unsafe {
            let ptr = handoff_addr as *const BootHandoff;
            if ptr.is_null() { return self.init_default(); }
            ptr.read_volatile()
        };

        if let Err(e) = handoff.validate() {
            if e.can_use_defaults() { return self.init_default(); }
            return Err(e);
        }

        self.setup_regions_from_handoff(&handoff)?;
        self.validate_layout()?;
        self.initialized = true;
        Ok(())
    }

    fn init_default(&mut self) -> BootMemoryResult<()> {
        self.regions.clear();
        self.add_region(CONVENTIONAL_MEMORY_START, CONVENTIONAL_MEMORY_END, RegionType::Reserved, 0);
        self.add_region(DEFAULT_KERNEL_START, DEFAULT_KERNEL_END, RegionType::Kernel, 0);
        self.add_region(DEFAULT_AVAILABLE_START, DEFAULT_AVAILABLE_END, RegionType::Available, 0);
        self.add_hardware_regions();
        self.find_next_free()?;
        self.calculate_totals();
        self.initialized = true;
        Ok(())
    }

    fn setup_regions_from_handoff(&mut self, handoff: &BootHandoff) -> BootMemoryResult<()> {
        self.regions.clear();
        self.add_region(CONVENTIONAL_MEMORY_START, CONVENTIONAL_MEMORY_END, RegionType::Reserved, 0);

        if handoff.kernel_size > 0 {
            self.add_region(handoff.kernel_base, handoff.kernel_base.saturating_add(handoff.kernel_size), RegionType::Kernel, 0);
        }
        if handoff.capsule_size > 0 {
            self.add_region(handoff.capsule_base, handoff.capsule_base.saturating_add(handoff.capsule_size), RegionType::Capsule, 0);
        }
        if handoff.memory_size > 0 {
            let start = align_up(handoff.memory_base, PAGE_SIZE_U64);
            let end = align_down(handoff.memory_base.saturating_add(handoff.memory_size), PAGE_SIZE_U64);
            if end > start { self.add_region(start, end, RegionType::Available, 0); }
        }

        self.add_hardware_regions();
        self.sort_regions();
        self.find_next_free()?;
        self.calculate_totals();
        Ok(())
    }

    fn add_hardware_regions(&mut self) {
        self.add_region(VGA_TEXT_START, VGA_TEXT_END, RegionType::Hardware, REGION_FLAG_UNCACHED);
        self.add_region(LEGACY_VIDEO_START, LEGACY_VIDEO_END, RegionType::Hardware, REGION_FLAG_UNCACHED);
        self.add_region(PCI_CONFIG_START, PCI_CONFIG_END, RegionType::Hardware, REGION_FLAG_UNCACHED);
        self.add_region(IOAPIC_BASE, IOAPIC_BASE + IOAPIC_SIZE, RegionType::Hardware, REGION_FLAG_UNCACHED);
        self.add_region(LAPIC_BASE, LAPIC_BASE + LAPIC_SIZE, RegionType::Hardware, REGION_FLAG_UNCACHED);
    }

    fn add_region(&mut self, start: u64, end: u64, region_type: RegionType, flags: u32) {
        if start >= end || self.regions.len() >= MAX_BOOT_REGIONS { return; }
        self.regions.push(MemoryRegion::new(start, end, region_type, flags));
    }

    fn sort_regions(&mut self) { self.regions.sort_by_key(|r| r.start.as_u64()); }

    fn find_next_free(&mut self) -> BootMemoryResult<()> {
        for region in &self.regions {
            if region.is_available() && region.size() >= PAGE_SIZE_U64 {
                self.next_free = region.start;
                return Ok(());
            }
        }
        Err(BootMemoryError::NoAvailableMemory)
    }

    fn calculate_totals(&mut self) {
        self.total_size = self.regions.iter().map(|r| r.size()).sum();
    }

    fn validate_layout(&self) -> BootMemoryResult<()> {
        if self.regions.is_empty() { return Err(BootMemoryError::NoRegionsDefined); }
        let mut has_available = false;
        for region in &self.regions {
            if region.start >= region.end { return Err(BootMemoryError::InvalidRegionBounds); }
            if region.is_available() { has_available = true; }
        }
        if !has_available { return Err(BootMemoryError::NoAvailableMemory); }
        Ok(())
    }

    fn allocate_aligned(&mut self, size: usize, alignment: usize) -> BootMemoryResult<PhysAddr> {
        if size == 0 { return Err(BootMemoryError::InvalidAlignment); }
        if size > MAX_ALLOCATION_SIZE { return Err(BootMemoryError::AllocationTooLarge); }

        let align = if alignment == 0 { PAGE_SIZE } else { alignment };
        if align & (align - 1) != 0 { return Err(BootMemoryError::InvalidAlignment); }

        let needed = align_up(size as u64, align as u64);
        let next_free_val = self.next_free.as_u64();

        for region in &self.regions {
            if !region.is_available() { continue; }
            let start = if next_free_val > region.start.as_u64() {
                align_up(next_free_val, align as u64)
            } else {
                align_up(region.start.as_u64(), align as u64)
            };
            let end = start.saturating_add(needed);

            if start >= region.start.as_u64() && end <= region.end.as_u64() {
                self.next_free = PhysAddr::new(end);
                self.allocated_size = self.allocated_size.saturating_add(needed);
                ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
                AVAILABLE_MEMORY.fetch_sub(needed, Ordering::Relaxed);
                return Ok(PhysAddr::new(start));
            }
        }
        Err(BootMemoryError::OutOfMemory)
    }

    fn get_region_stats(&self) -> RegionStats {
        let mut stats = RegionStats::default();
        for region in &self.regions {
            let size = region.size();
            stats.total_memory = stats.total_memory.saturating_add(size);
            match region.region_type {
                RegionType::Available => stats.available_memory = stats.available_memory.saturating_add(size),
                RegionType::Reserved => stats.reserved_memory = stats.reserved_memory.saturating_add(size),
                RegionType::Kernel => stats.kernel_memory = stats.kernel_memory.saturating_add(size),
                RegionType::Capsule => stats.capsule_memory = stats.capsule_memory.saturating_add(size),
                RegionType::Hardware => stats.hardware_memory = stats.hardware_memory.saturating_add(size),
                RegionType::Defective => stats.defective_memory = stats.defective_memory.saturating_add(size),
            }
        }
        stats.allocated_memory = self.allocated_size;
        stats.region_count = self.regions.len();
        stats
    }
}

#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 || align & (align - 1) != 0 { return value; }
    (value.saturating_add(align - 1)) & !(align - 1)
}

#[inline]
const fn align_down(value: u64, align: u64) -> u64 {
    if align == 0 || align & (align - 1) != 0 { return value; }
    value & !(align - 1)
}

// Public API
pub fn init(handoff_addr: u64) -> BootMemoryResult<()> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    if guard.is_some() { return Err(BootMemoryError::AlreadyInitialized); }

    let mut manager = BootMemoryManager::new();
    manager.init_from_handoff(handoff_addr)?;

    let stats = manager.get_region_stats();
    TOTAL_MEMORY.store(stats.total_memory, Ordering::Relaxed);
    AVAILABLE_MEMORY.store(stats.available_memory, Ordering::Relaxed);

    *guard = Some(manager);
    Ok(())
}

pub fn allocate_pages(count: usize) -> BootMemoryResult<PhysAddr> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    guard.as_mut().ok_or(BootMemoryError::NotInitialized)?.allocate_aligned(count * PAGE_SIZE, PAGE_SIZE)
}

pub fn allocate_aligned(size: usize, align: usize) -> BootMemoryResult<PhysAddr> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    guard.as_mut().ok_or(BootMemoryError::NotInitialized)?.allocate_aligned(size, align)
}

pub fn get_stats() -> Option<RegionStats> {
    BOOT_MEMORY_MANAGER.lock().as_ref().map(|m| m.get_region_stats())
}

pub fn get_available_regions() -> Vec<MemoryRegion> {
    BOOT_MEMORY_MANAGER.lock().as_ref().map(|m| m.regions.iter().filter(|r| r.is_available()).copied().collect()).unwrap_or_default()
}

pub fn get_all_regions() -> Vec<MemoryRegion> {
    BOOT_MEMORY_MANAGER.lock().as_ref().map(|m| m.regions.clone()).unwrap_or_default()
}

pub fn find_region(addr: PhysAddr) -> Option<MemoryRegion> {
    BOOT_MEMORY_MANAGER.lock().as_ref().and_then(|m| m.regions.iter().find(|r| r.contains(addr)).copied())
}

#[inline]
pub fn total_memory() -> u64 { TOTAL_MEMORY.load(Ordering::Relaxed) }
#[inline]
pub fn available_memory() -> u64 { AVAILABLE_MEMORY.load(Ordering::Relaxed) }
#[inline]
pub fn allocation_count() -> usize { ALLOCATION_COUNT.load(Ordering::Relaxed) }
pub fn is_initialized() -> bool { BOOT_MEMORY_MANAGER.lock().is_some() }
