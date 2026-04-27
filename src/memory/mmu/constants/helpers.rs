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

use super::pte::{PTE_ADDR_MASK, PTE_PRESENT};

pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const PAGE_SIZE: usize = 4096;

#[inline]
pub const fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}
#[inline]
pub const fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}
#[inline]
pub const fn pd_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}
#[inline]
pub const fn pt_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}
#[inline]
pub const fn pte_is_present(entry: u64) -> bool {
    entry & PTE_PRESENT != 0
}
#[inline]
pub const fn pte_address(entry: u64) -> u64 {
    entry & PTE_ADDR_MASK
}
