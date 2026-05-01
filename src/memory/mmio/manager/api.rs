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

extern crate alloc;
use super::super::error::MmioResult;
use super::super::stats::MMIO_STATS;
use super::super::types::{MmioFlags, MmioRegion, MmioStatsSnapshot};
use super::core::MmioManager;
use alloc::vec::Vec;
use spin::Mutex;
use crate::memory::addr::{PhysAddr, VirtAddr};

pub(super) static MMIO_MANAGER: Mutex<MmioManager> = Mutex::new(MmioManager::new());

pub fn init() -> MmioResult<()> {
    MMIO_MANAGER.lock().init()
}

pub fn map_mmio(pa: PhysAddr, size: usize, flags: MmioFlags) -> MmioResult<VirtAddr> {
    let mut mgr = MMIO_MANAGER.lock();
    if !mgr.is_initialized() {
        mgr.init()?;
    }
    mgr.map_region(pa, size, flags)
}

pub fn map_device_memory(pa: PhysAddr, size: usize) -> MmioResult<VirtAddr> {
    map_mmio(pa, size, MmioFlags::device())
}

pub fn map_framebuffer(pa: PhysAddr, size: usize) -> MmioResult<VirtAddr> {
    map_mmio(pa, size, MmioFlags::framebuffer())
}

pub fn unmap_mmio(va: VirtAddr) -> MmioResult<()> {
    MMIO_MANAGER.lock().unmap_region(va)
}

pub fn get_region_info(va: VirtAddr) -> Option<MmioRegion> {
    MMIO_MANAGER.lock().find_region(va).copied()
}

pub fn list_regions() -> Vec<MmioRegion> {
    MMIO_MANAGER.lock().regions().copied().collect()
}
pub fn get_mapped_regions() -> Vec<MmioRegion> {
    list_regions()
}
pub fn get_stats() -> MmioStatsSnapshot {
    MMIO_STATS.snapshot()
}

pub fn validate_mmio_access(va: VirtAddr, size: usize) -> bool {
    MMIO_MANAGER
        .lock()
        .find_region(va)
        .map(|r| va.as_u64() + size as u64 <= r.va.as_u64() + r.size as u64)
        .unwrap_or(false)
}

pub fn is_mmio_region(va: VirtAddr) -> bool {
    MMIO_MANAGER.lock().find_region(va).is_some()
}
