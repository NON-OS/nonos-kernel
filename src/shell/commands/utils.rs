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

pub fn trim_bytes(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1);
    if start < end { &s[start..end] } else { &[] }
}

pub fn starts_with(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && &s[..prefix.len()] == prefix
}

pub fn format_size(buf: &mut [u8], bytes: usize) -> usize {
    if bytes >= 1024 * 1024 * 1024 {
        let gb = bytes / (1024 * 1024 * 1024);
        let mb = (bytes % (1024 * 1024 * 1024)) / (1024 * 1024);
        format_num_unit(buf, gb, mb / 100, b" GB")
    } else if bytes >= 1024 * 1024 {
        let mb = bytes / (1024 * 1024);
        let kb = (bytes % (1024 * 1024)) / 1024;
        format_num_unit(buf, mb, kb / 100, b" MB")
    } else if bytes >= 1024 {
        let kb = bytes / 1024;
        format_num_unit(buf, kb, 0, b" KB")
    } else {
        format_num_unit(buf, bytes, 0, b" B")
    }
}

pub fn format_num_unit(buf: &mut [u8], whole: usize, frac: usize, unit: &[u8]) -> usize {
    let mut pos = 0;

    if whole == 0 {
        buf[pos] = b'0';
        pos += 1;
    } else {
        let mut n = whole;
        let mut digits = [0u8; 20];
        let mut dpos = 0;
        while n > 0 {
            digits[dpos] = b'0' + (n % 10) as u8;
            n /= 10;
            dpos += 1;
        }
        while dpos > 0 {
            dpos -= 1;
            buf[pos] = digits[dpos];
            pos += 1;
        }
    }

    if frac > 0 {
        buf[pos] = b'.';
        pos += 1;
        buf[pos] = b'0' + (frac % 10) as u8;
        pos += 1;
    }

    buf[pos..pos+unit.len()].copy_from_slice(unit);
    pos += unit.len();

    pos
}

pub fn format_decimal(buf: &mut [u8], mut val: u64) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut digits = [0u8; 20];
    let mut pos = 0;
    while val > 0 {
        digits[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }

    for i in 0..pos {
        buf[i] = digits[pos - 1 - i];
    }
    pos
}

pub fn format_num_simple(buf: &mut [u8], val: usize) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut n = val;
    let mut digits = [0u8; 16];
    let mut pos = 0;
    while n > 0 {
        digits[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        pos += 1;
    }

    for i in 0..pos {
        buf[i] = digits[pos - 1 - i];
    }
    pos
}

pub fn write_right_aligned(buf: &mut [u8], start: usize, val: usize, width: usize) -> usize {
    let mut num_buf = [0u8; 16];
    let len = format_num_simple(&mut num_buf, val);

    let padding = if width > len { width - len } else { 1 };
    for i in 0..padding {
        buf[start + i] = b' ';
    }

    buf[start + padding..start + padding + len].copy_from_slice(&num_buf[..len]);
    start + padding + len
}

pub fn write_size_col(buf: &mut [u8], bytes: usize) -> usize {
    let mb = bytes / (1024 * 1024);
    let len = format_num_simple(buf, mb);
    buf[len] = b'M';
    let total = len + 1;
    let pad = if total < 7 { 7 - total } else { 1 };
    for i in 0..pad {
        buf[total + i] = b' ';
    }
    total + pad
}

pub fn format_hex_byte(buf: &mut [u8], val: u8) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    buf[0] = HEX[(val >> 4) as usize];
    buf[1] = HEX[(val & 0xF) as usize];
}
