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

pub(super) fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i32 + b as i32 - c as i32;
    let pa = (p - a as i32).abs();
    let pb = (p - b as i32).abs();
    let pc = (p - c as i32).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

pub(super) fn unfilter_row(
    filter_type: u8,
    raw: &[u8],
    prev_row: &[u8],
    channels: usize,
) -> Option<alloc::vec::Vec<u8>> {
    extern crate alloc;
    use alloc::vec::Vec;
    let mut current_row = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        let a = if i >= channels { current_row[i - channels] } else { 0u8 };
        let b = prev_row[i];
        let c = if i >= channels { prev_row[i - channels] } else { 0u8 };
        let val = match filter_type {
            0 => raw[i],
            1 => raw[i].wrapping_add(a),
            2 => raw[i].wrapping_add(b),
            3 => raw[i].wrapping_add(((a as u16 + b as u16) / 2) as u8),
            4 => raw[i].wrapping_add(paeth_predictor(a, b, c)),
            _ => return None,
        };
        current_row.push(val);
    }
    Some(current_row)
}
