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

use alloc::vec::Vec;
use core::str;

pub(super) fn bytes_to_str(bytes: &[u8]) -> Option<&str> {
    str::from_utf8(bytes).ok()
}

pub(super) fn split_args(s: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_word = false;

    for (i, &c) in s.iter().enumerate() {
        if c == b' ' {
            if in_word {
                result.push(&s[start..i]);
                in_word = false;
            }
        } else {
            if !in_word {
                start = i;
                in_word = true;
            }
        }
    }

    if in_word {
        result.push(&s[start..]);
    }

    result
}

pub(super) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(super) fn parse_usize(s: &[u8]) -> Option<usize> {
    let mut result: usize = 0;
    for &c in s {
        if c < b'0' || c > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((c - b'0') as usize)?;
    }
    Some(result)
}

pub(super) fn hex_char(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}
