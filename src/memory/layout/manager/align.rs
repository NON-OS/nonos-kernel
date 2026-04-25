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

use super::super::constants::PAGE_SIZE_U64;

#[inline(always)]
pub const fn align_down(x: u64, a: u64) -> u64 {
    if a == 0 || (a & (a - 1)) != 0 {
        return x;
    }
    x & !(a - 1)
}
#[inline(always)]
pub const fn align_up(x: u64, a: u64) -> u64 {
    if a == 0 || (a & (a - 1)) != 0 {
        return x;
    }
    (x + a - 1) & !(a - 1)
}
#[inline(always)]
pub const fn is_aligned(x: u64, a: u64) -> bool {
    if a == 0 {
        return false;
    }
    (x & (a - 1)) == 0
}
#[inline(always)]
pub const fn is_page_aligned(addr: u64) -> bool {
    is_aligned(addr, PAGE_SIZE_U64)
}
