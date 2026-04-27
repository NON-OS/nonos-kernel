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

use super::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::write_user_value;

pub fn handle_getrlimit(resource: u32, rlim: u64) -> SyscallResult {
    if rlim == 0 {
        return errno(14);
    }

    let (soft, hard): (u64, u64) = match resource {
        0 => (0x7FFFFFFF, 0x7FFFFFFF),
        1 => (0x7FFFFFFF, 0x7FFFFFFF),
        2 => (0x7FFFFFFF, 0x7FFFFFFF),
        3 => (8 * 1024 * 1024, 8 * 1024 * 1024),
        4 => (0, 0x7FFFFFFF),
        5 => (0x7FFFFFFF, 0x7FFFFFFF),
        6 => (4096, 4096),
        7 => (1024, 4096),
        _ => (0x7FFFFFFF, 0x7FFFFFFF),
    };

    if write_user_value(rlim, &soft).is_err() {
        return errno(14);
    }
    if write_user_value(rlim + 8, &hard).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_setrlimit(resource: u32, rlim: u64) -> SyscallResult {
    if rlim == 0 {
        return errno(14);
    }

    let _ = resource;
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_prlimit64(pid: i32, resource: u32, new_limit: u64, old_limit: u64) -> SyscallResult {
    if old_limit != 0 {
        let result = handle_getrlimit(resource, old_limit);
        if result.value < 0 {
            return result;
        }
    }

    if new_limit != 0 {
        let _ = pid;
        let result = handle_setrlimit(resource, new_limit);
        if result.value < 0 {
            return result;
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
