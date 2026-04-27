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

pub(super) fn printable_string_equal(a: &[u8], b: &[u8]) -> bool {
    normalize_printable(a) == normalize_printable(b)
}

fn normalize_printable(s: &[u8]) -> alloc::vec::Vec<u8> {
    let mut result = alloc::vec::Vec::with_capacity(s.len());
    let mut in_space = true;
    for &b in s {
        if b == b' ' {
            if !in_space {
                result.push(b' ');
                in_space = true;
            }
        } else {
            result.push(b.to_ascii_lowercase());
            in_space = false;
        }
    }
    if result.last() == Some(&b' ') {
        result.pop();
    }
    result
}
