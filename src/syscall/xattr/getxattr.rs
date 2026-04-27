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

use super::storage::{XattrStorage, XATTR_NAME_MAX};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;

pub fn handle_getxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64) -> SyscallResult {
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
    let resolved = match crate::fs::vfs::resolve_path(&path) {
        Ok(p) => p,
        Err(_) => return errno(2),
    };
    match XattrStorage::get(&resolved, &name) {
        Ok(value) => {
            if size == 0 {
                return SyscallResult {
                    value: value.len() as i64,
                    capability_consumed: false,
                    audit_required: false,
                };
            }
            if value.len() > size as usize {
                return errno(34);
            }
            if value_ptr != 0 && copy_to_user(value_ptr, &value).is_err() {
                return errno(14);
            }
            SyscallResult {
                value: value.len() as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        Err(e) => errno(e),
    }
}
