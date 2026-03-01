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

use alloc::{string::String, string::ToString, vec::Vec};

use super::error::{PathError, PathResult};
use super::types::MAX_PATH_LEN;

pub fn cstr_to_string(ptr: *const u8) -> PathResult<String> {
    if ptr.is_null() {
        return Err(PathError::NullPointer);
    }

    let mut bytes = Vec::with_capacity(256);
    let mut offset = 0usize;

    loop {
        // SAFETY: Caller guarantees ptr is valid
        let byte = unsafe { core::ptr::read(ptr.add(offset)) };

        if byte == 0 {
            break;
        }

        if offset >= MAX_PATH_LEN {
            return Err(PathError::TooLong);
        }

        bytes.push(byte);
        offset += 1;
    }

    core::str::from_utf8(&bytes)
        .map(|s| s.to_string())
        .map_err(|_| PathError::InvalidUtf8)
}

pub fn cstr_to_string_bounded(ptr: *const u8, max_len: usize) -> PathResult<String> {
    if ptr.is_null() {
        return Err(PathError::NullPointer);
    }

    let limit = max_len.min(MAX_PATH_LEN);
    let mut bytes = Vec::with_capacity(limit.min(256));
    let mut offset = 0usize;

    while offset < limit {
        let byte = unsafe { core::ptr::read(ptr.add(offset)) };

        if byte == 0 {
            break;
        }

        bytes.push(byte);
        offset += 1;
    }

    if offset >= limit {
        return Err(PathError::TooLong);
    }

    core::str::from_utf8(&bytes)
        .map(|s| s.to_string())
        .map_err(|_| PathError::InvalidUtf8)
}

pub fn cstr_to_string_legacy(ptr: *const u8) -> Result<String, &'static str> {
    cstr_to_string(ptr).map_err(|e| e.as_str())
}
