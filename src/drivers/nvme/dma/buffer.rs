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

use x86_64::{PhysAddr, VirtAddr};

use super::super::error::NvmeError;
use super::prp::PrpBuilder;
use super::region::DmaRegion;

pub struct TransferBuffer {
    region: DmaRegion,
}

impl TransferBuffer {
    pub fn allocate(size: usize) -> Result<Self, NvmeError> {
        let region = DmaRegion::allocate(size)?;
        Ok(Self { region })
    }

    #[inline]
    pub const fn phys_addr(&self) -> PhysAddr {
        self.region.phys_addr()
    }

    #[inline]
    pub const fn virt_addr(&self) -> VirtAddr {
        self.region.virt_addr()
    }

    #[inline]
    pub const fn size(&self) -> usize {
        self.region.size()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.region.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.region.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.region.zero();
    }

    pub fn copy_from(&mut self, src: &[u8]) {
        self.region.copy_from(src);
    }

    pub fn copy_to(&self, dst: &mut [u8]) {
        self.region.copy_to(dst);
    }

    pub fn build_prps(&self, transfer_size: usize) -> Result<PrpBuilder, NvmeError> {
        let size = core::cmp::min(transfer_size, self.region.size());
        PrpBuilder::build(self.region.phys_addr(), size)
    }
}
