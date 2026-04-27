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

use super::load::load_filter_from_user;
use super::state::{add_filter, set_strict_mode};
use super::types::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_seccomp(operation: u32, flags: u32, args: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);
    match operation {
        SECCOMP_SET_MODE_STRICT => do_strict_mode(pid),
        SECCOMP_SET_MODE_FILTER => do_filter_mode(pid, flags, args),
        SECCOMP_GET_ACTION_AVAIL => do_get_action_avail(args),
        SECCOMP_GET_NOTIF_SIZES => do_get_notif_sizes(args),
        _ => errno(22),
    }
}

fn do_strict_mode(pid: u32) -> SyscallResult {
    match set_strict_mode(pid) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => errno(e),
    }
}

fn do_filter_mode(pid: u32, flags: u32, args: u64) -> SyscallResult {
    if args == 0 {
        return errno(14);
    }
    let filter = match load_filter_from_user(args, flags) {
        Ok(f) => f,
        Err(e) => return errno(e),
    };
    match add_filter(pid, filter) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(e) => errno(e),
    }
}

fn do_get_action_avail(args: u64) -> SyscallResult {
    let action: u32 = match read_user_value(args) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let supported = matches!(
        action & SECCOMP_RET_ACTION_FULL,
        SECCOMP_RET_ALLOW
            | SECCOMP_RET_KILL_PROCESS
            | SECCOMP_RET_KILL_THREAD
            | SECCOMP_RET_TRAP
            | SECCOMP_RET_ERRNO
            | SECCOMP_RET_TRACE
            | SECCOMP_RET_LOG
    );
    if supported {
        SyscallResult { value: 0, capability_consumed: false, audit_required: false }
    } else {
        errno(95)
    }
}

fn do_get_notif_sizes(args: u64) -> SyscallResult {
    if args == 0 {
        return errno(14);
    }
    let sizes = SeccompNotifSizes { seccomp_notif: 80, seccomp_notif_resp: 24, seccomp_data: 64 };
    match write_user_value(args, &sizes) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(14),
    }
}
