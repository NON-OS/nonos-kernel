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

use super::super::super::constants::align_up;
use super::super::super::error::{MmioError, MmioResult};
use super::types::MmioManager;
use crate::memory::layout;
use x86_64::VirtAddr;

impl MmioManager {
    pub fn init(&mut self) -> MmioResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.next_vaddr = layout::MMIO_BASE;
        self.regions.clear();
        self.initialized = true;
        Ok(())
    }

    pub(super) fn allocate_virtual_range(&mut self, size: usize) -> MmioResult<VirtAddr> {
        if !self.initialized {
            return Err(MmioError::NotInitialized);
        }
        let aligned_size = align_up(size, layout::PAGE_SIZE);
        let aligned_addr = align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;
        if aligned_addr + aligned_size as u64 > layout::MMIO_BASE + layout::MMIO_SIZE {
            return Err(MmioError::AddressSpaceExhausted);
        }
        self.next_vaddr = aligned_addr + aligned_size as u64;
        Ok(VirtAddr::new(aligned_addr))
    }
}
