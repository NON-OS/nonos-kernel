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

use alloc::string::String;

pub(super) fn skip_dns_name(data: &[u8], off: &mut usize) -> Result<(), &'static str> {
    if *off >= data.len() {
        return Err("dns name overflow");
    }
    if data[*off] & 0xC0 == 0xC0 {
        *off += 2;
    } else {
        while *off < data.len() && data[*off] != 0 {
            let len = data[*off] as usize;
            if len > 63 {
                return Err("dns invalid label");
            }
            *off += 1 + len;
        }
        if *off < data.len() {
            *off += 1;
        }
    }
    Ok(())
}

pub(super) fn parse_dns_name(data: &[u8], off: usize) -> Result<String, &'static str> {
    let mut name = String::new();
    let mut pos = off;
    let mut jumps = 0;
    while pos < data.len() {
        let len = data[pos];
        if len == 0 {
            break;
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return Err("dns ptr overflow");
            }
            let ptr = ((len as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if ptr >= data.len() {
                return Err("dns invalid ptr");
            }
            jumps += 1;
            if jumps > 10 {
                return Err("dns too many jumps");
            }
            pos = ptr;
        } else {
            let label_len = len as usize;
            if pos + 1 + label_len > data.len() {
                return Err("dns label overflow");
            }
            if !name.is_empty() {
                name.push('.');
            }
            for i in 0..label_len {
                name.push(data[pos + 1 + i] as char);
            }
            pos += 1 + label_len;
        }
    }
    if name.is_empty() {
        name.push('.');
    }
    Ok(name)
}

pub(super) fn skip_questions(
    data: &[u8],
    off: &mut usize,
    qd_count: usize,
) -> Result<(), &'static str> {
    for _ in 0..qd_count {
        skip_dns_name(data, off)?;
        *off += 4;
        if *off > data.len() {
            return Err("dns malformed qd");
        }
    }
    Ok(())
}
