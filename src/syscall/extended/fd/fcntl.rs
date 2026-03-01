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

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

pub fn handle_fcntl(fd: i32, cmd: i32, arg: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    const F_DUPFD: i32 = 0;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const F_DUPFD_CLOEXEC: i32 = 1030;

    const O_NONBLOCK: u64 = 0x800;
    const O_APPEND: u64 = 0x400;

    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min_fd = arg as i32;
            match crate::fs::fd::fd_dup_min(fd, min_fd) {
                Ok(new_fd) => {
                    if cmd == F_DUPFD_CLOEXEC {
                        if crate::fs::fd::fd_set_cloexec(new_fd, true).is_err() {
                            let _ = crate::fs::fd::fd_close(new_fd);
                            return errno(9);
                        }
                    }
                    SyscallResult { value: new_fd as i64, capability_consumed: false, audit_required: false }
                }
                Err(_) => errno(24),
            }
        }
        F_GETFD => {
            let cloexec = match crate::fs::fd::fd_get_cloexec(fd) {
                Ok(b) => b,
                Err(_) => return errno(9),
            };
            SyscallResult { value: if cloexec { 1 } else { 0 }, capability_consumed: false, audit_required: false }
        }
        F_SETFD => {
            let cloexec = (arg & 1) != 0;
            match crate::fs::fd::fd_set_cloexec(fd, cloexec) {
                Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
                Err(_) => errno(9),
            }
        }
        F_GETFL => {
            let flags = match crate::fs::fd::fd_get_flags(fd) {
                Ok(f) => f,
                Err(_) => return errno(9),
            };
            SyscallResult { value: flags as i64, capability_consumed: false, audit_required: false }
        }
        F_SETFL => {
            let allowed_mask = O_APPEND | O_NONBLOCK;
            let new_flags = (arg as u32) & (allowed_mask as u32);
            match crate::fs::fd::fd_set_flags(fd, new_flags as i32) {
                Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
                Err(_) => errno(9),
            }
        }
        _ => errno(22),
    }
}
