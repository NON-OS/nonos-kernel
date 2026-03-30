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

use super::super::constants::pages_needed;
use super::region::DmaRegion;

impl DmaRegion {
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.size) }
    }

    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.size) }
    }

    pub fn zero(&mut self) {
        unsafe {
            core::ptr::write_bytes(self.as_mut_ptr(), 0, self.size);
        }
    }

    pub const fn is_dma32(&self) -> bool {
        self.dma32_compatible
    }

    pub const fn page_count(&self) -> usize {
        pages_needed(self.size)
    }
}
