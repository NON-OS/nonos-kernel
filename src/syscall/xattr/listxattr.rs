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

use super::storage::XattrStorage;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;
use alloc::vec::Vec;

pub fn handle_listxattr(path_ptr: u64, list_ptr: u64, size: u64) -> SyscallResult {
    if path_ptr == 0 {
        return errno(14);
    }
    let path = match crate::syscall::dispatch::util::parse_string_from_user(path_ptr, 4096) {
        Ok(p) => p,
        Err(_) => return errno(14),
    };
    let resolved = match crate::fs::vfs::resolve_path(&path) {
        Ok(p) => p,
        Err(_) => return errno(2),
    };
    match XattrStorage::list(&resolved) {
        Ok(names) => {
            let mut buf: Vec<u8> = Vec::new();
            for name in &names {
                buf.extend_from_slice(name.as_bytes());
                buf.push(0);
            }
            if size == 0 {
                return SyscallResult {
                    value: buf.len() as i64,
                    capability_consumed: false,
                    audit_required: false,
                };
            }
            if buf.len() > size as usize {
                return errno(34);
            }
            if list_ptr != 0 && !buf.is_empty() && copy_to_user(list_ptr, &buf).is_err() {
                return errno(14);
            }
            SyscallResult {
                value: buf.len() as i64,
                capability_consumed: false,
                audit_required: false,
            }
        }
        Err(e) => errno(e),
    }
}
