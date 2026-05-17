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

pub const DISPLAY_MAX: usize = 24;

pub fn format(value: i64, decimal_pos: u8, out: &mut [u8]) -> usize {
    let int_part = value / 100;
    let dec_part = (value % 100).abs();
    let mut buf = [0u8; DISPLAY_MAX];
    let mut n = 0;
    n += write_int(int_part, &mut buf[n..]);
    if decimal_pos > 0 || dec_part != 0 {
        if n < buf.len() {
            buf[n] = b'.';
            n += 1;
        }
        if n < buf.len() {
            buf[n] = b'0' + (dec_part / 10) as u8;
            n += 1;
        }
        if n < buf.len() {
            buf[n] = b'0' + (dec_part % 10) as u8;
            n += 1;
        }
    }
    let len = n.min(out.len());
    out[..len].copy_from_slice(&buf[..len]);
    len
}

fn write_int(value: i64, out: &mut [u8]) -> usize {
    if value == 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'0';
        return 1;
    }
    let neg = value < 0;
    let mut v = if neg { (value as i128).unsigned_abs() } else { value as u128 };
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut n = 0;
    if neg && n < out.len() {
        out[n] = b'-';
        n += 1;
    }
    while len > 0 && n < out.len() {
        len -= 1;
        out[n] = tmp[len];
        n += 1;
    }
    n
}
