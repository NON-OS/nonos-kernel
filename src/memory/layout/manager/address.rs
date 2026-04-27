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
use core::ops::Range;

#[inline(always)]
pub const fn in_kernel_space(va: u64) -> bool {
    va >= CANONICAL_HIGH_MIN
}
#[inline(always)]
pub const fn in_user_space(va: u64) -> bool {
    va <= USER_TOP
}
#[inline(always)]
pub const fn is_canonical(va: u64) -> bool {
    in_user_space(va) || in_kernel_space(va)
}
#[inline(always)]
pub const fn range(base: u64, size: u64) -> Range<u64> {
    base..(base.saturating_add(size))
}

#[inline(always)]
pub const fn selfref_l4_va() -> u64 {
    let i = SELFREF_SLOT as u64;
    (SIGN_EXTEND_MASK << SIGN_EXTEND_SHIFT)
        | (i << PML4_SHIFT)
        | (i << PDPT_SHIFT)
        | (i << PD_SHIFT)
        | (i << PT_SHIFT)
}
