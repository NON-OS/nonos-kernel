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

use super::storage::{XattrStorage, XATTR_NAME_MAX, XATTR_SIZE_MAX};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;
use alloc::vec;

pub fn handle_setxattr(
    path_ptr: u64,
    name_ptr: u64,
    value_ptr: u64,
    size: u64,
    flags: i32,
) -> SyscallResult {
    if path_ptr == 0 || name_ptr == 0 {
        return errno(14);
    }
    let path = match crate::syscall::dispatch::util::parse_string_from_user(path_ptr, 4096) {
        Ok(p) => p,
        Err(_) => return errno(14),
    };
    let name =
        match crate::syscall::dispatch::util::parse_string_from_user(name_ptr, XATTR_NAME_MAX) {
            Ok(n) => n,
            Err(_) => return errno(14),
        };
    if size > XATTR_SIZE_MAX as u64 {
        return errno(34);
    }
    let mut value = vec![0u8; size as usize];
    if size > 0 && value_ptr != 0 {
        if copy_from_user(value_ptr, &mut value).is_err() {
            return errno(14);
        }
    }
    let resolved = match crate::fs::vfs::resolve_path(&path) {
        Ok(p) => p,
        Err(_) => return errno(2),
    };
    match XattrStorage::set(&resolved, &name, &value, flags) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => errno(e),
    }
}
