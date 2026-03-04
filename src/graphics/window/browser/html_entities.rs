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

extern crate alloc;

use alloc::string::String;

pub(super) fn parse_decimal(bytes: &[u8]) -> Option<u32> {
    let mut result: u32 = 0;
    for &b in bytes {
        if b >= b'0' && b <= b'9' {
            result = result.saturating_mul(10).saturating_add((b - b'0') as u32);
        } else {
            return None;
        }
    }
    Some(result)
}

pub(super) fn parse_hex(bytes: &[u8]) -> Option<u32> {
    let mut result: u32 = 0;
    for &b in bytes {
        let digit = if b >= b'0' && b <= b'9' {
            b - b'0'
        } else if b >= b'a' && b <= b'f' {
            b - b'a' + 10
        } else if b >= b'A' && b <= b'F' {
            b - b'A' + 10
        } else {
            return None;
        };
        result = result.saturating_mul(16).saturating_add(digit as u32);
    }
    Some(result)
}

pub(super) fn try_parse_entity(remaining: &[u8], current_line: &mut String) -> Option<usize> {
    if remaining.starts_with(b"&nbsp;") {
        current_line.push(' ');
        return Some(6);
    } else if remaining.starts_with(b"&lt;") {
        current_line.push('<');
        return Some(4);
    } else if remaining.starts_with(b"&gt;") {
        current_line.push('>');
        return Some(4);
    } else if remaining.starts_with(b"&amp;") {
        current_line.push('&');
        return Some(5);
    } else if remaining.starts_with(b"&quot;") {
        current_line.push('"');
        return Some(6);
    } else if remaining.starts_with(b"&apos;") {
        current_line.push('\'');
        return Some(6);
    } else if remaining.starts_with(b"&copy;") {
        current_line.push_str("(c)");
        return Some(6);
    } else if remaining.starts_with(b"&reg;") {
        current_line.push_str("(R)");
        return Some(5);
    } else if remaining.starts_with(b"&trade;") {
        current_line.push_str("(TM)");
        return Some(7);
    } else if remaining.starts_with(b"&mdash;") {
        current_line.push_str("--");
        return Some(7);
    } else if remaining.starts_with(b"&ndash;") {
        current_line.push('-');
        return Some(7);
    } else if remaining.starts_with(b"&hellip;") {
        current_line.push_str("...");
        return Some(8);
    } else if remaining.starts_with(b"&bull;") {
        current_line.push_str(" * ");
        return Some(6);
    } else if remaining.starts_with(b"&lsquo;") || remaining.starts_with(b"&rsquo;") {
        current_line.push('\'');
        return Some(7);
    } else if remaining.starts_with(b"&ldquo;") || remaining.starts_with(b"&rdquo;") {
        current_line.push('"');
        return Some(7);
    } else if remaining.starts_with(b"&euro;") {
        current_line.push_str("EUR");
        return Some(6);
    } else if remaining.starts_with(b"&pound;") {
        current_line.push_str("GBP");
        return Some(7);
    } else if remaining.starts_with(b"&yen;") {
        current_line.push_str("JPY");
        return Some(5);
    } else if remaining.starts_with(b"&#") {
        if let Some(end_pos) = remaining[2..].iter().position(|&b| b == b';') {
            let num_str = &remaining[2..2 + end_pos];
            let code = if num_str.starts_with(b"x") || num_str.starts_with(b"X") {
                parse_hex(&num_str[1..])
            } else {
                parse_decimal(num_str)
            };
            if let Some(c) = code {
                if c >= 32 && c < 127 {
                    current_line.push(c as u8 as char);
                } else if c == 160 {
                    current_line.push(' ');
                }
            }
            return Some(3 + end_pos);
        }
    }
    None
}
