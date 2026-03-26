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

pub fn format_size(size: u32, buf: &mut [u8; 10]) {
    buf.fill(0);
    if size < 1024 {
        format_bytes(size, buf);
    } else if size < 1024 * 1024 {
        format_kb(size / 1024, buf);
    } else {
        format_mb(size / (1024 * 1024), buf);
    }
}

fn format_bytes(size: u32, buf: &mut [u8; 10]) {
    if size == 0 {
        buf[0..3].copy_from_slice(b"0 B");
        return;
    }
    let mut n = size;
    let mut digits = [0u8; 5];
    let mut i = 0;
    while n > 0 {
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0;
    while i > 0 {
        i -= 1;
        buf[j] = digits[i];
        j += 1;
    }
    buf[j] = b' ';
    buf[j + 1] = b'B';
}

fn format_kb(kb: u32, buf: &mut [u8; 10]) {
    if kb >= 100 {
        buf[0] = b'0' + (kb / 100) as u8;
        buf[1] = b'0' + ((kb / 10) % 10) as u8;
        buf[2] = b'0' + (kb % 10) as u8;
        buf[3..6].copy_from_slice(b" KB");
    } else {
        buf[0] = b'0' + (kb / 10) as u8;
        buf[1] = b'0' + (kb % 10) as u8;
        buf[2..5].copy_from_slice(b" KB");
    }
}

fn format_mb(mb: u32, buf: &mut [u8; 10]) {
    buf[0] = b'0' + (mb / 10) as u8;
    buf[1] = b'0' + (mb % 10) as u8;
    buf[2..5].copy_from_slice(b" MB");
}
