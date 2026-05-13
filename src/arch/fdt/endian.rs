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

use super::error::FdtError;

#[inline]
pub fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, FdtError> {
    let slice = bytes.get(offset..offset + 4).ok_or(FdtError::OutOfBounds)?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
pub fn be_u64(bytes: &[u8], offset: usize) -> Result<u64, FdtError> {
    let hi = be_u32(bytes, offset)? as u64;
    let lo = be_u32(bytes, offset + 4)? as u64;
    Ok((hi << 32) | lo)
}

// FDT specs 32/64-bit cells inside `reg` and similar property arrays.
// `cells` is 1 or 2 (FDT v17 caps it at 2; higher is rare and rejected).
#[inline]
pub fn be_cells(bytes: &[u8], offset: usize, cells: u32) -> Result<u64, FdtError> {
    match cells {
        1 => be_u32(bytes, offset).map(|v| v as u64),
        2 => be_u64(bytes, offset),
        _ => Err(FdtError::OutOfBounds),
    }
}
