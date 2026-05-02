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

use super::flags::MmioFlags;
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::mmio::ordering::Mmio;

#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    pub va: VirtAddr,
    pub pa: PhysAddr,
    pub size: usize,
    pub flags: MmioFlags,
    pub region_id: u64,
}

impl MmioRegion {
    pub const fn new(
        va: VirtAddr,
        pa: PhysAddr,
        size: usize,
        flags: MmioFlags,
        region_id: u64,
    ) -> Self {
        Self { va, pa, size, flags, region_id }
    }

    pub fn end_va(&self) -> VirtAddr {
        VirtAddr::new(self.va.as_u64() + self.size as u64)
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        let start = self.va.as_u64();
        let end = start + self.size as u64;
        let a = addr.as_u64();
        a >= start && a < end
    }

    pub fn validate_access(&self, offset: usize, access_size: usize) -> bool {
        offset.checked_add(access_size).map(|end| end <= self.size).unwrap_or(false)
    }

    pub fn offset_addr(&self, offset: usize) -> Option<VirtAddr> {
        if offset < self.size {
            Some(VirtAddr::new(self.va.as_u64() + offset as u64))
        } else {
            None
        }
    }

    /// Vend a typed accessor for a register at `offset` within this
    /// mapped region. Returns `None` if `offset + size_of::<T>()` would
    /// fall outside the region.
    ///
    /// # Safety
    ///
    /// ek@nonos.systems
    ///
    /// The caller asserts that the device exposes a register of width
    /// `T` at exactly this offset, with the device-protocol semantics
    /// the caller intends. The bounds check confirms the bytes lie
    /// within the kernel-mapped region; it cannot confirm that the
    /// device interprets them as `T`. Passing the wrong width or an
    /// offset that lands between two registers will produce undefined
    /// device behaviour.
    pub unsafe fn accessor<T: Copy>(&self, offset: usize) -> Option<Mmio<T>> {
        if !self.validate_access(offset, core::mem::size_of::<T>()) {
            return None;
        }
        let va = VirtAddr::new(self.va.as_u64() + offset as u64);
        // SAFETY: ek@nonos.systems — the manager mapped this region with
        // device-memory page attributes when it produced `MmioRegion`;
        // the bounds check above proves `size_of::<T>()` bytes at `va`
        // fall inside the mapping. The width-and-protocol assertion is
        // covered by the surrounding fn's own unsafe contract.
        Some(unsafe { Mmio::<T>::from_addr(va) })
    }
}
