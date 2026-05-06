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

//! Length-prefixed reads with explicit upper bounds. The caller
//! supplies the cap so a hostile producer cannot inflate userland
//! memory by claiming a multi-MB string for a field that should
//! never exceed a hundred bytes.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::error::DecodeError;
use super::reader::Reader;

pub(super) fn bounded_string(r: &mut Reader<'_>, cap: u32) -> Result<String, DecodeError> {
    let bytes = bounded_bytes(r, cap)?;
    String::from_utf8(bytes).map_err(|_| DecodeError::BadUtf8)
}

pub(super) fn bounded_bytes(r: &mut Reader<'_>, cap: u32) -> Result<Vec<u8>, DecodeError> {
    let len = r.u32()?;
    if len > cap {
        return Err(DecodeError::TooLarge);
    }
    let slice = r.take(len as usize)?;
    Ok(slice.to_vec())
}

pub(super) fn bounded_count(r: &mut Reader<'_>, cap: u32) -> Result<u32, DecodeError> {
    let n = r.u32()?;
    if n > cap {
        return Err(DecodeError::TooManyItems);
    }
    Ok(n)
}
