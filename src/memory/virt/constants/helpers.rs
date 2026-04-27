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

use super::pte_flags::{PTE_ADDR_MASK, PTE_PRESENT};
use super::table::{
    L1_INDEX_SHIFT, L2_INDEX_SHIFT, L3_INDEX_SHIFT, L4_INDEX_SHIFT, PAGE_TABLE_INDEX_MASK,
};

#[inline]
pub const fn l4_index(va: u64) -> usize {
    ((va >> L4_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn l3_index(va: u64) -> usize {
    ((va >> L3_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn l2_index(va: u64) -> usize {
    ((va >> L2_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn l1_index(va: u64) -> usize {
    ((va >> L1_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn pte_is_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

#[inline]
pub const fn pte_address(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}
