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

use super::super::error::SafetyResult;
use super::api::{validate_read, validate_write};
use core::ptr;

pub fn safe_copy(src: u64, dst: u64, size: usize) -> SafetyResult<()> {
    validate_read(src, size)?;
    validate_write(dst, size)?;
    unsafe {
        ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, size);
    }
    Ok(())
}

pub fn safe_zero(addr: u64, size: usize) -> SafetyResult<()> {
    validate_write(addr, size)?;
    unsafe {
        ptr::write_bytes(addr as *mut u8, 0, size);
    }
    Ok(())
}
