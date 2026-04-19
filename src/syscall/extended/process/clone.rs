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
use crate::usercopy::copy_from_user;

pub fn handle_clone(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64) -> SyscallResult {
    match crate::process::clone_process(flags, stack, parent_tid, child_tid, tls) {
        Ok(tid) => SyscallResult { value: tid as i64, capability_consumed: false, audit_required: true },
        Err(errno_val) => SyscallResult { value: errno_val as i64, capability_consumed: false, audit_required: false },
    }
}

/// Helper macro to safely convert slice to array, returning EINVAL on failure
macro_rules! safe_u64_from_slice {
    ($buf:expr, $start:expr, $end:expr) => {
        match $buf[$start..$end].try_into() {
            Ok(arr) => u64::from_ne_bytes(arr),
            Err(_) => return errno(22),
        }
    };
}

pub fn handle_clone3(args_ptr: u64, size: u64) -> SyscallResult {
    if args_ptr == 0 { return errno(14); }
    let expected_size = core::mem::size_of::<crate::process::CloneArgs>();
    if (size as usize) < expected_size { return errno(22); }
    let mut buf = [0u8; 88];
    if copy_from_user(args_ptr, &mut buf).is_err() { return errno(14); }
    // SAFETY: All conversions use safe macro that returns EINVAL on failure
    let args = crate::process::CloneArgs {
        flags: safe_u64_from_slice!(buf, 0, 8),
        pidfd: safe_u64_from_slice!(buf, 8, 16),
        child_tid: safe_u64_from_slice!(buf, 16, 24),
        parent_tid: safe_u64_from_slice!(buf, 24, 32),
        exit_signal: safe_u64_from_slice!(buf, 32, 40),
        stack: safe_u64_from_slice!(buf, 40, 48),
        stack_size: safe_u64_from_slice!(buf, 48, 56),
        tls: safe_u64_from_slice!(buf, 56, 64),
        set_tid: safe_u64_from_slice!(buf, 64, 72),
        set_tid_size: safe_u64_from_slice!(buf, 72, 80),
        cgroup: safe_u64_from_slice!(buf, 80, 88),
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
        Err(e) => match e {
            "no current process" => errno(3),
            "invalid executable format" => errno(8),
            "executable has no entry point" => errno(8),
            "failed to setup user stack" => errno(12),
            "no valid cr3 for process" => errno(14),
            _ => errno(2),
        },
    }
}
