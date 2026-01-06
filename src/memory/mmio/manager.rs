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

extern crate alloc;
use alloc::collections::BTreeMap;
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
use super::error::{MmioError, MmioResult};
use super::stats::MMIO_STATS;
use super::types::{MmioFlags, MmioRegion};
use crate::memory::layout;
// ============================================================================
// MMIO MANAGER
// ============================================================================
pub struct MmioManager {
    regions: BTreeMap<VirtAddr, MmioRegion>,
    next_vaddr: u64,
    initialized: bool,
}

impl MmioManager {
    pub const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            next_vaddr: layout::MMIO_BASE,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> MmioResult<()> {
        if self.initialized {
            return Ok(());
        }

        self.next_vaddr = layout::MMIO_BASE;
        self.regions.clear();
        self.initialized = true;

        Ok(())
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn allocate_virtual_range(&mut self, size: usize) -> MmioResult<VirtAddr> {
        if !self.initialized {
            return Err(MmioError::NotInitialized);
        }

        let aligned_size = align_up(size, layout::PAGE_SIZE);
        let aligned_addr = align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;
        if aligned_addr + aligned_size as u64 > layout::MMIO_BASE + layout::MMIO_SIZE {
            return Err(MmioError::AddressSpaceExhausted);
        }

        let virt_addr = VirtAddr::new(aligned_addr);
        self.next_vaddr = aligned_addr + aligned_size as u64;

        Ok(virt_addr)
    }

    pub fn map_region(
        &mut self,
        pa: PhysAddr,
        size: usize,
        flags: MmioFlags,
    ) -> MmioResult<VirtAddr> {
        if size == 0 {
            return Err(MmioError::InvalidSize);
        }

        if pa.as_u64() % layout::PAGE_SIZE as u64 != 0 {
            return Err(MmioError::NotPageAligned);
        }

        let va = self.allocate_virtual_range(size)?;
        let aligned_size = align_up(size, layout::PAGE_SIZE);
        let page_count = aligned_size / layout::PAGE_SIZE;
        let vm_flags = flags.to_vm_flags();
        for i in 0..page_count {
            let page_offset = i * layout::PAGE_SIZE;
            let page_va = VirtAddr::new(va.as_u64() + page_offset as u64);
            let page_pa = PhysAddr::new(pa.as_u64() + page_offset as u64);
            self.map_page(page_va, page_pa, vm_flags)?;
        }

        let region_id = MMIO_STATS.next_id();
        let region = MmioRegion::new(va, pa, aligned_size, flags, region_id);
        self.regions.insert(va, region);
        MMIO_STATS.record_mapping(aligned_size);

        Ok(va)
    }

    pub fn unmap_region(&mut self, va: VirtAddr) -> MmioResult<()> {
        let region = self
            .regions
            .remove(&va)
            .ok_or(MmioError::RegionNotFound)?;
        let page_count = region.size / layout::PAGE_SIZE;
        for i in 0..page_count {
            let page_offset = i * layout::PAGE_SIZE;
            let page_va = VirtAddr::new(va.as_u64() + page_offset as u64);
            self.unmap_page(page_va)?;
        }

        MMIO_STATS.record_unmapping(region.size);

        Ok(())
    }

    pub fn find_region(&self, va: VirtAddr) -> Option<&MmioRegion> {
        self.regions.values().find(|region| region.contains(va))
    }

    pub fn validate_access(
        &self,
        va: VirtAddr,
        offset: usize,
        access_size: usize,
    ) -> MmioResult<&MmioRegion> {
        let region = self
            .find_region(va)
            .ok_or(MmioError::InvalidBaseAddress)?;
        if !region.validate_access(offset, access_size) {
            return Err(MmioError::AccessOutOfBounds);
        }

        Ok(region)
    }

    pub fn regions(&self) -> impl Iterator<Item = &MmioRegion> {
        self.regions.values()
    }

    fn map_page(&self, va: VirtAddr, pa: PhysAddr, vm_flags: u32) -> MmioResult<()> {
        use crate::memory::virt;
        let writable = (vm_flags & VM_FLAG_WRITABLE) != 0;
        let executable = (vm_flags & VM_FLAG_NX) == 0;
        let user = (vm_flags & VM_FLAG_USER) != 0;

        // SAFETY: Mapping device memory to kernel-controlled region
        virt::map_page_4k(va, pa, writable, user, executable)
            .map_err(|_| MmioError::MappingFailed)
    }

    /// Unmaps a single page.
    fn unmap_page(&self, va: VirtAddr) -> MmioResult<()> {
        use crate::memory::virt;
        // SAFETY: Unmapping previously mapped MMIO page
        virt::unmap_page(va).map_err(|_| MmioError::UnmapFailed)
    }
}

impl Default for MmioManager {
    fn default() -> Self {
        Self::new()
    }
}
// ============================================================================
// GLOBAL STATE
// ============================================================================
use alloc::vec::Vec;
use spin::Mutex;
use super::ops;
static MMIO_MANAGER: Mutex<MmioManager> = Mutex::new(MmioManager::new());
// ============================================================================
// PUBLIC API
// ============================================================================
pub fn init() -> MmioResult<()> {
    MMIO_MANAGER.lock().init()
}

pub fn map_mmio(pa: PhysAddr, size: usize, flags: MmioFlags) -> MmioResult<VirtAddr> {
    MMIO_MANAGER.lock().map_region(pa, size, flags)
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

pub unsafe fn read8(va: VirtAddr, offset: usize) -> MmioResult<u8> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_8)?;
    Ok(ops::read8_at(va.as_u64() + offset as u64))
}

pub unsafe fn read16(va: VirtAddr, offset: usize) -> MmioResult<u16> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_16)?;
    Ok(ops::read16_at(va.as_u64() + offset as u64))
}

pub unsafe fn read32(va: VirtAddr, offset: usize) -> MmioResult<u32> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_32)?;
    Ok(ops::read32_at(va.as_u64() + offset as u64))
}

pub unsafe fn read64(va: VirtAddr, offset: usize) -> MmioResult<u64> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_64)?;
    Ok(ops::read64_at(va.as_u64() + offset as u64))
}

pub unsafe fn write8(va: VirtAddr, offset: usize, value: u8) -> MmioResult<()> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_8)?;
    ops::write8_at(va.as_u64() + offset as u64, value);
    Ok(())
}

pub unsafe fn write16(va: VirtAddr, offset: usize, value: u16) -> MmioResult<()> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_16)?;
    ops::write16_at(va.as_u64() + offset as u64, value);
    Ok(())
}

pub unsafe fn write32(va: VirtAddr, offset: usize, value: u32) -> MmioResult<()> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_32)?;
    ops::write32_at(va.as_u64() + offset as u64, value);
    Ok(())
}

pub unsafe fn write64(va: VirtAddr, offset: usize, value: u64) -> MmioResult<()> {
    let manager = MMIO_MANAGER.lock();
    let _region = manager.validate_access(va, offset, ACCESS_SIZE_64)?;
    ops::write64_at(va.as_u64() + offset as u64, value);
    Ok(())
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

pub fn get_stats() -> super::types::MmioStatsSnapshot {
    MMIO_STATS.snapshot()
}

pub fn validate_mmio_access(va: VirtAddr, size: usize) -> bool {
    MMIO_MANAGER
        .lock()
        .find_region(va)
        .map(|region| {
            let region_end = region.va.as_u64() + region.size as u64;
            va.as_u64() + size as u64 <= region_end
        })
        .unwrap_or(false)
}

pub fn is_mmio_region(va: VirtAddr) -> bool {
    MMIO_MANAGER.lock().find_region(va).is_some()
}
