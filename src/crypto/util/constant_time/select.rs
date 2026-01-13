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

#[inline(always)]
pub fn ct_select_u8(cond: bool, a: u8, b: u8) -> u8 {
    let mask = (-(cond as i8)) as u8;
    (mask & a) | (!mask & b)
}

#[inline(always)]
pub fn ct_select_u16(cond: bool, a: u16, b: u16) -> u16 {
    let mask = (-(cond as i16)) as u16;
    (mask & a) | (!mask & b)
}

#[inline(always)]
pub fn ct_select_u32(cond: bool, a: u32, b: u32) -> u32 {
    let mask = (-(cond as i32)) as u32;
    (mask & a) | (!mask & b)
}

#[inline(always)]
pub fn ct_select_u64(cond: bool, a: u64, b: u64) -> u64 {
    let mask = (-(cond as i64)) as u64;
    (mask & a) | (!mask & b)
}

#[inline(always)]
pub fn ct_select_usize(cond: bool, a: usize, b: usize) -> usize {
    let mask = (-(cond as isize)) as usize;
    (mask & a) | (!mask & b)
}

#[inline(always)]
pub fn ct_select_u64_bit(cond_bit: u64, a: u64, b: u64) -> u64 {
    let mask = 0u64.wrapping_sub(cond_bit);
    (mask & a) | (!mask & b)
}
