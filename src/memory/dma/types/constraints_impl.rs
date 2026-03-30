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

use super::super::constants::*;
use super::constraints::DmaConstraints;
use crate::memory::layout;

impl DmaConstraints {
    pub fn is_satisfied(&self, phys_addr: u64, size: usize) -> bool {
        if phys_addr % self.alignment as u64 != 0 {
            return false;
        }

        if self.dma32_only && !is_range_dma32_compatible(phys_addr, size) {
            return false;
        }

        if size > self.max_segment_size {
            return false;
        }

        true
    }
}

impl Default for DmaConstraints {
    fn default() -> Self {
        Self {
            alignment: layout::PAGE_SIZE,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: true,
        }
    }
}
