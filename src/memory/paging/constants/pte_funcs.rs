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

use super::pte_flags::*;

#[inline]
pub const fn pte_is_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

#[inline]
pub const fn pte_is_huge(pte: u64) -> bool {
    pte & PTE_HUGE_PAGE != 0
}

#[inline]
pub const fn pte_address(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}

#[inline]
pub const fn pte_is_writable(pte: u64) -> bool {
    pte & PTE_WRITABLE != 0
}
