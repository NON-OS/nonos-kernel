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

use alloc::vec::Vec;

pub const MAX_STR: usize = 2048;

/// `s` cut to at most `MAX_STR` bytes on a char boundary.
pub fn cap(s: &str) -> &str {
    let mut n = s.len().min(MAX_STR);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Appends `s`, capped to `MAX_STR`, after its `u16` length.
pub fn put_str(out: &mut Vec<u8>, s: &str) {
    let s = cap(s);
    put_u16(out, s.len() as u16);
    out.extend_from_slice(s.as_bytes());
}
