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

// A 4 KiB page-table frame is a 512-entry u64 array. The
// bootloader writes through the UEFI identity map to populate
// these pages; `phys` is the bus-side address that ends up in CR3
// or in a parent table's pointer entry.

#[derive(Debug, Clone, Copy)]
pub struct PageTable {
    pub phys: u64,
}

impl PageTable {
    pub fn from_phys(phys: u64) -> Self {
        Self { phys }
    }

    // SAFETY: caller guarantees `phys` is a valid 4-KiB-aligned
    // physical frame currently identity-mapped writable (true
    // during UEFI Boot Services and the bootloader's pre-jump
    // window).
    pub unsafe fn write_entry(&self, index: usize, value: u64) {
        let table = unsafe { &mut *(self.phys as *mut [u64; 512]) };
        table[index] = value;
    }

    pub unsafe fn read_entry(&self, index: usize) -> u64 {
        let table = unsafe { &*(self.phys as *const [u64; 512]) };
        table[index]
    }
}
