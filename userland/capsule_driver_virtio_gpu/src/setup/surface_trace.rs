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

use crate::debug;

pub fn primary(width: u32, height: u32, pages: u64) {
    let mut line = [0u8; 80];
    let mut pos = 0usize;
    pos += copy(&mut line[pos..], b"primary surface ");
    pos += write_u32(&mut line[pos..], width);
    pos += copy(&mut line[pos..], b"x");
    pos += write_u32(&mut line[pos..], height);
    pos += copy(&mut line[pos..], b" pages=");
    pos += write_u32(&mut line[pos..], pages as u32);
    debug::marker(&line[..pos]);
}

fn copy(dst: &mut [u8], src: &[u8]) -> usize {
    let n = if src.len() > dst.len() { dst.len() } else { src.len() };
    dst[..n].copy_from_slice(&src[..n]);
    n
}

fn write_u32(dst: &mut [u8], mut v: u32) -> usize {
    if v == 0 && !dst.is_empty() {
        dst[0] = b'0';
        return 1;
    }
    let mut buf = [0u8; 10];
    let mut len = 0;
    while v > 0 && len < buf.len() {
        buf[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let out = if len > dst.len() { dst.len() } else { len };
    for i in 0..out {
        dst[i] = buf[len - 1 - i];
    }
    out
}
