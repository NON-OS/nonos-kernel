// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::error::{VmError, VmResult};
use super::super::types::{MappedRange, VmFlags};
use super::core::VirtualMemoryManager;
use crate::memory::addr::{PhysAddr, VirtAddr};

impl VirtualMemoryManager {
    pub fn translate(&self, va: VirtAddr) -> VmResult<(PhysAddr, VmFlags, usize)> {
        if !self.initialized {
            return Err(VmError::NotInitialized);
        }
        if let Some(range) = self.find_mapped_range(va) {
            let offset = va.as_u64() - range.start_va.as_u64();
            let pa = PhysAddr::new(range.start_pa.as_u64() + offset);
            Ok((pa, range.flags, range.size))
        } else {
            Err(VmError::AddressNotMapped)
        }
    }

    pub fn find_mapped_range(&self, va: VirtAddr) -> Option<&MappedRange> {
        self.mapped_ranges.iter().find(|range| range.contains(va))
    }
}
