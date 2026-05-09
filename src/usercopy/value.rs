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

//! Typed `Copy` accessors over the directmap byte path. The user
//! pointer is alignment-checked first; the byte transfer reuses
//! `copy.rs`.

use super::copy::{copy_from_user, copy_to_user};
use super::error::UsercopyError;

pub fn read_user_value<T: Copy>(user_ptr: u64) -> Result<T, UsercopyError> {
    let size = core::mem::size_of::<T>();
    let align = core::mem::align_of::<T>();
    if align > 1 && (user_ptr as usize) % align != 0 {
        return Err(UsercopyError::MisalignedAddress);
    }
    let mut value: T = unsafe { core::mem::zeroed() };
    let dst = unsafe { core::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, size) };
    copy_from_user(user_ptr, dst)?;
    Ok(value)
}

pub fn write_user_value<T: Copy>(user_ptr: u64, value: &T) -> Result<(), UsercopyError> {
    let size = core::mem::size_of::<T>();
    let align = core::mem::align_of::<T>();
    if align > 1 && (user_ptr as usize) % align != 0 {
        return Err(UsercopyError::MisalignedAddress);
    }
    let src = unsafe { core::slice::from_raw_parts(value as *const T as *const u8, size) };
    copy_to_user(user_ptr, src)
}
