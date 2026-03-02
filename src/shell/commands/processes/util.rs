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

use crate::shell::commands::utils::format_num_simple;

pub(super) fn parse_number(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }

    let mut result: u64 = 0;
    for &c in s {
        if c < b'0' || c > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(result)
}

pub(super) fn parse_signed_number(s: &[u8]) -> Option<i32> {
    if s.is_empty() {
        return None;
    }

    let (negative, start) = if s[0] == b'-' {
        (true, 1)
    } else if s[0] == b'+' {
        (false, 1)
    } else {
        (false, 0)
    };

    if start >= s.len() {
        return None;
    }

    let mut val: i32 = 0;
    for &b in &s[start..] {
        if b >= b'0' && b <= b'9' {
            val = val.checked_mul(10)?.checked_add((b - b'0') as i32)?;
        } else {
            return None;
        }
    }

    if negative {
        Some(-val)
    } else {
        Some(val)
    }
}

pub(super) fn format_nice_value(buf: &mut [u8], nice: i32) -> usize {
    if nice < 0 {
        buf[0] = b'-';
        1 + format_num_simple(&mut buf[1..], (-nice) as usize)
    } else {
        format_num_simple(buf, nice as usize)
    }
}

pub(super) fn split_first_word(s: &[u8]) -> (&[u8], &[u8]) {
    let mut end = 0;
    while end < s.len() && s[end] != b' ' && s[end] != b'\t' {
        end += 1;
    }
    let first = &s[..end];
    let rest = if end < s.len() { &s[end+1..] } else { &[] };
    (first, rest)
}

pub(super) fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i+needle.len()] == needle {
            return true;
        }
    }
    false
}
