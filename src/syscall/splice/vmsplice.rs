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

use super::types::IoVec;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, read_user_value};
use alloc::vec;

pub fn handle_vmsplice(fd: i32, iov_ptr: u64, nr_segs: u64, _flags: u32) -> SyscallResult {
    if iov_ptr == 0 || nr_segs == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }
    if nr_segs > 1024 {
        return errno(22);
    }
    let mut total = 0i64;
    for i in 0..nr_segs as usize {
        let iov_addr = iov_ptr + (i * core::mem::size_of::<IoVec>()) as u64;
        let iov: IoVec = match read_user_value(iov_addr) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        if !iov.is_valid() {
            return errno(14);
        }
        if iov.iov_len == 0 {
            continue;
        }
        let mut buf = vec![0u8; iov.iov_len as usize];
        if copy_from_user(iov.iov_base, &mut buf).is_err() {
            return errno(14);
        }
        let result =
            crate::syscall::dispatch::file_io::handle_write(fd, buf.as_ptr() as u64, iov.iov_len);
        if result.value < 0 {
            if total > 0 {
                return SyscallResult {
                    value: total,
                    capability_consumed: false,
                    audit_required: false,
                };
            }
            return result;
        }
        total += result.value;
    }
    SyscallResult { value: total, capability_consumed: false, audit_required: false }
}
