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

use super::flags::IsaFlags;

// `riscv,isa` is a NUL-terminated lowercase string like "rv64imafdc".
// Single-letter extensions appear as bare characters. Multi-letter
// extensions appear after an `_` (we ignore them here; F/D/V/C/A are
// all single-letter). The "g" alias expands to IMAFD.
pub fn parse(s: &[u8]) -> IsaFlags {
    let mut flags = IsaFlags::default();
    // Skip optional NUL terminator coming in from FDT strings.
    let body = match s.iter().position(|&b| b == 0) {
        Some(end) => &s[..end],
        None => s,
    };
    // Strip the "rvXX" prefix; the rest of the leading run before any
    // underscore is the single-letter extension list.
    let after_xlen = strip_xlen_prefix(body);
    for &c in after_xlen {
        if c == b'_' {
            break;
        }
        match c {
            b'a' => flags.a = true,
            b'c' => flags.c = true,
            b'd' => flags.d = true,
            b'f' => flags.f = true,
            b'g' => {
                flags.a = true;
                flags.f = true;
                flags.d = true;
            }
            b'v' => flags.v = true,
            _ => {}
        }
    }
    flags
}

fn strip_xlen_prefix(s: &[u8]) -> &[u8] {
    // Common prefixes: "rv32", "rv64", "rv128". Skip "rv" + digits.
    let mut i = 0;
    if s.len() >= 2 && s[0] == b'r' && s[1] == b'v' {
        i = 2;
        while i < s.len() && s[i].is_ascii_digit() {
            i += 1;
        }
    }
    &s[i..]
}
