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

use crate::arch::x86_64::vga::{set_color, write_str, Color};

pub(super) fn write_to_stdout(data: &[u8]) -> u64 {
    for &byte in data {
        if byte.is_ascii() {
            write_str(unsafe { core::str::from_utf8_unchecked(&[byte]) });
        }
    }
    data.len() as u64
}

pub(super) fn write_to_stderr(data: &[u8]) -> u64 {
    set_color(Color::LightRed, Color::Black);
    for &byte in data {
        if byte.is_ascii() {
            write_str(unsafe { core::str::from_utf8_unchecked(&[byte]) });
        }
    }
    set_color(Color::LightGray, Color::Black);
    data.len() as u64
}
