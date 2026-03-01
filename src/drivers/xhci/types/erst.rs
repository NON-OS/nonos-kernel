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

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ErstEntry {
    pub ring_base_lo: u32,
    pub ring_base_hi: u32,
    pub ring_size: u32,
    pub reserved: u32,
}

impl ErstEntry {
    pub fn new(base_addr: u64, size: u32) -> Self {
        Self {
            ring_base_lo: (base_addr & 0xFFFF_FFFF) as u32,
            ring_base_hi: (base_addr >> 32) as u32,
            ring_size: size,
            reserved: 0,
        }
    }

    pub fn ring_base(&self) -> u64 {
        (self.ring_base_lo as u64) | ((self.ring_base_hi as u64) << 32)
    }
}
