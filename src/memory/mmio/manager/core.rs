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
use alloc::collections::BTreeMap;
use x86_64::{PhysAddr, VirtAddr};
use super::super::constants::*;
use super::super::error::{MmioError, MmioResult};
use super::super::stats::MMIO_STATS;
use super::super::types::{MmioFlags, MmioRegion};
use crate::memory::layout;

pub struct MmioManager { pub(super) regions: BTreeMap<VirtAddr, MmioRegion>, pub(super) next_vaddr: u64, pub(super) initialized: bool }

impl MmioManager {
    pub const fn new() -> Self { Self { regions: BTreeMap::new(), next_vaddr: layout::MMIO_BASE, initialized: false } }
    pub fn init(&mut self) -> MmioResult<()> { if self.initialized { return Ok(()); } self.next_vaddr = layout::MMIO_BASE; self.regions.clear(); self.initialized = true; Ok(()) }
    #[inline] pub fn is_initialized(&self) -> bool { self.initialized }

    pub(super) fn allocate_virtual_range(&mut self, size: usize) -> MmioResult<VirtAddr> {
        if !self.initialized { return Err(MmioError::NotInitialized); }
        let aligned_size = align_up(size, layout::PAGE_SIZE); let aligned_addr = align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;
        if aligned_addr + aligned_size as u64 > layout::MMIO_BASE + layout::MMIO_SIZE { return Err(MmioError::AddressSpaceExhausted); }
        self.next_vaddr = aligned_addr + aligned_size as u64; Ok(VirtAddr::new(aligned_addr))
    }

    pub fn map_region(&mut self, pa: PhysAddr, size: usize, flags: MmioFlags) -> MmioResult<VirtAddr> {
        if size == 0 { return Err(MmioError::InvalidSize); }
        if pa.as_u64() % layout::PAGE_SIZE as u64 != 0 { return Err(MmioError::NotPageAligned); }
        let va = self.allocate_virtual_range(size)?; let aligned_size = align_up(size, layout::PAGE_SIZE); let page_count = aligned_size / layout::PAGE_SIZE; let vm_flags = flags.to_vm_flags();
        for i in 0..page_count { self.map_page(VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64), PhysAddr::new(pa.as_u64() + (i * layout::PAGE_SIZE) as u64), vm_flags)?; }
        let region = MmioRegion::new(va, pa, aligned_size, flags, MMIO_STATS.next_id());
        self.regions.insert(va, region); MMIO_STATS.record_mapping(aligned_size); Ok(va)
    }

    pub fn unmap_region(&mut self, va: VirtAddr) -> MmioResult<()> {
        let region = self.regions.remove(&va).ok_or(MmioError::RegionNotFound)?;
        for i in 0..(region.size / layout::PAGE_SIZE) { self.unmap_page(VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64))?; }
        MMIO_STATS.record_unmapping(region.size); Ok(())
    }

    pub fn find_region(&self, va: VirtAddr) -> Option<&MmioRegion> { self.regions.values().find(|r| r.contains(va)) }
    pub fn validate_access(&self, va: VirtAddr, offset: usize, access_size: usize) -> MmioResult<&MmioRegion> {
        let region = self.find_region(va).ok_or(MmioError::InvalidBaseAddress)?;
        if !region.validate_access(offset, access_size) { return Err(MmioError::AccessOutOfBounds); } Ok(region)
    }
    pub fn regions(&self) -> impl Iterator<Item = &MmioRegion> { self.regions.values() }

    fn map_page(&self, va: VirtAddr, pa: PhysAddr, vm_flags: u32) -> MmioResult<()> {
        use crate::memory::virt;
        virt::map_page_4k(va, pa, (vm_flags & VM_FLAG_WRITABLE) != 0, (vm_flags & VM_FLAG_USER) != 0, (vm_flags & VM_FLAG_NX) == 0).map_err(|_| MmioError::MappingFailed)
    }
    fn unmap_page(&self, va: VirtAddr) -> MmioResult<()> { crate::memory::virt::unmap_page(va).map_err(|_| MmioError::UnmapFailed) }
}

impl Default for MmioManager { fn default() -> Self { Self::new() } }
