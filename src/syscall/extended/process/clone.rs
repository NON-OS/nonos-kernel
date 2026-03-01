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

pub fn handle_clone(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) -> SyscallResult {
    match crate::process::clone_process(flags, stack, parent_tid, child_tid, tls) {
        Ok(tid) => SyscallResult { value: tid as i64, capability_consumed: false, audit_required: true },
        Err(errno_val) => SyscallResult { value: errno_val as i64, capability_consumed: false, audit_required: false },
    }
}

pub fn handle_clone3(args_ptr: u64, size: u64) -> SyscallResult {
    if args_ptr == 0 {
        return errno(14);
    }

    let args = unsafe {
        core::ptr::read(args_ptr as *const crate::process::CloneArgs)
    };

    match crate::process::clone3(&args, size as usize) {
        Ok(tid) => SyscallResult { value: tid as i64, capability_consumed: false, audit_required: true },
        Err(errno_val) => SyscallResult { value: errno_val as i64, capability_consumed: false, audit_required: false },
    }
}

pub fn handle_execveat(dirfd: i32, pathname: u64, argv: u64, envp: u64, flags: i32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = crate::syscall::extended::filesystem::resolve_path_at(dirfd, &path);
    let _ = (argv, envp, flags);

    match crate::process::exec_fn(&full_path) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(2),
    }
}
