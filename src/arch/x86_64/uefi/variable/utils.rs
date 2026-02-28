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

use crate::arch::x86_64::uefi::constants::MAX_VARIABLE_NAME_LENGTH;
use crate::arch::x86_64::uefi::error::UefiError;

pub fn name_to_ucs2(name: &str) -> Result<[u16; MAX_VARIABLE_NAME_LENGTH], UefiError> {
    if name.len() >= MAX_VARIABLE_NAME_LENGTH {
        return Err(UefiError::VariableNameTooLong {
            length: name.len(),
            max_length: MAX_VARIABLE_NAME_LENGTH - 1,
        });
    }

    let mut buf = [0u16; MAX_VARIABLE_NAME_LENGTH];
    for (i, ch) in name.chars().enumerate() {
        if i >= MAX_VARIABLE_NAME_LENGTH - 1 {
            break;
        }
        buf[i] = ch as u16;
    }
    Ok(buf)
}

pub fn ucs2_to_string(ucs2: &[u16]) -> String {
    let end = ucs2.iter().position(|&c| c == 0).unwrap_or(ucs2.len());
    String::from_utf16_lossy(&ucs2[..end])
}
