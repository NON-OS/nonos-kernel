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

use crate::arch::x86_64::acpi::tables::sdt::SdtHeader;
use core::mem;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Slit {
    pub header: SdtHeader,
    pub locality_count: u64,
}

impl Slit {
    pub const LOCAL_DISTANCE: u8 = 10;
    pub const UNREACHABLE: u8 = 255;

    pub fn matrix_offset(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub fn matrix_size(&self) -> usize {
        let count = self.locality_count as usize;
        count * count
    }

    pub fn distance(&self, from: usize, to: usize) -> Option<u8> {
        let count = self.locality_count as usize;
        if from >= count || to >= count {
            return None;
        }
        unsafe {
            let matrix = (self as *const Self as *const u8).add(mem::size_of::<Self>());
            Some(*matrix.add(from * count + to))
        }
    }

    pub fn is_valid(&self) -> bool {
        let count = self.locality_count as usize;
        if count == 0 {
            return false;
        }
        for i in 0..count {
            if self.distance(i, i) != Some(Self::LOCAL_DISTANCE) {
                return false;
            }
        }
        true
    }

    pub fn is_symmetric(&self) -> bool {
        let count = self.locality_count as usize;
        for i in 0..count {
            for j in (i + 1)..count {
                if self.distance(i, j) != self.distance(j, i) {
                    return false;
                }
            }
        }
        true
    }
}
