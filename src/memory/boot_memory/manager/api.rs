// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::super::constants::PAGE_SIZE;
use super::super::error::{BootMemoryError, BootMemoryResult};
use super::super::types::{MemoryRegion, RegionStats};
use super::state::{
    BootMemoryManager, ALLOCATION_COUNT, AVAILABLE_MEMORY, BOOT_MEMORY_MANAGER, TOTAL_MEMORY,
};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use crate::memory::addr::PhysAddr;

pub fn init(handoff_addr: u64) -> BootMemoryResult<()> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    if guard.is_some() {
        return Err(BootMemoryError::AlreadyInitialized);
    }

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
    guard
        .as_mut()
        .ok_or(BootMemoryError::NotInitialized)?
        .allocate_aligned(count * PAGE_SIZE, PAGE_SIZE)
}

pub fn allocate_aligned(size: usize, align: usize) -> BootMemoryResult<PhysAddr> {
    let mut guard = BOOT_MEMORY_MANAGER.lock();
    guard.as_mut().ok_or(BootMemoryError::NotInitialized)?.allocate_aligned(size, align)
}

pub fn get_stats() -> Option<RegionStats> {
    BOOT_MEMORY_MANAGER.lock().as_ref().map(|m| m.get_region_stats())
}

pub fn get_available_regions() -> Vec<MemoryRegion> {
    BOOT_MEMORY_MANAGER
        .lock()
        .as_ref()
        .map(|m| m.regions.iter().filter(|r| r.is_available()).copied().collect())
        .unwrap_or_default()
}

pub fn get_all_regions() -> Vec<MemoryRegion> {
    BOOT_MEMORY_MANAGER.lock().as_ref().map(|m| m.regions.clone()).unwrap_or_default()
}

pub fn find_region(addr: PhysAddr) -> Option<MemoryRegion> {
    BOOT_MEMORY_MANAGER
        .lock()
        .as_ref()
        .and_then(|m| m.regions.iter().find(|r| r.contains(addr)).copied())
}

#[inline]
pub fn total_memory() -> u64 {
    TOTAL_MEMORY.load(Ordering::Relaxed)
}

#[inline]
pub fn available_memory() -> u64 {
    AVAILABLE_MEMORY.load(Ordering::Relaxed)
}

#[inline]
pub fn allocation_count() -> usize {
    ALLOCATION_COUNT.load(Ordering::Relaxed)
}

pub fn is_initialized() -> bool {
    BOOT_MEMORY_MANAGER.lock().is_some()
}
