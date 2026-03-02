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

pub fn parse_ipv4(input: &[u8]) -> Option<[u8; 4]> {
    let s = core::str::from_utf8(input).ok()?;
    let mut result = [0u8; 4];
    let mut idx = 0;

    for part in s.split('.') {
        if idx >= 4 {
            return None;
        }
        result[idx] = part.parse().ok()?;
        idx += 1;
    }

    if idx == 4 {
        Some(result)
    } else {
        None
    }
}

pub fn write_u64(buf: &mut [u8], val: u64) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = val;
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

pub fn write_ip(buf: &mut [u8], ip: [u8; 4]) -> usize {
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 {
            buf[pos] = b'.';
            pos += 1;
        }
        if octet >= 100 {
            buf[pos] = b'0' + (octet / 100);
            pos += 1;
        }
        if octet >= 10 {
            buf[pos] = b'0' + ((octet / 10) % 10);
            pos += 1;
        }
        buf[pos] = b'0' + (octet % 10);
        pos += 1;
    }
    pos
}

pub fn write_mac(buf: &mut [u8], mac: [u8; 6]) -> usize {
    let hex = b"0123456789ab";
    let mut pos = 0;
    for (i, &b) in mac.iter().enumerate() {
        if i > 0 {
            buf[pos] = b':';
            pos += 1;
        }
        buf[pos] = hex[(b >> 4) as usize];
        buf[pos + 1] = hex[(b & 0xF) as usize];
        pos += 2;
    }
    pos
}
