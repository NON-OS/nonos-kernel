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

pub fn handle_clone3(args_ptr: u64, size: u64) -> SyscallResult {
    if args_ptr == 0 { return errno(14); }
    let expected_size = core::mem::size_of::<crate::process::CloneArgs>();
    if (size as usize) < expected_size { return errno(22); }
    let mut buf = [0u8; 88];
    if copy_from_user(args_ptr, &mut buf).is_err() { return errno(14); }
    let args = crate::process::CloneArgs {
        flags: u64::from_ne_bytes(buf[0..8].try_into().unwrap()),
        pidfd: u64::from_ne_bytes(buf[8..16].try_into().unwrap()),
        child_tid: u64::from_ne_bytes(buf[16..24].try_into().unwrap()),
        parent_tid: u64::from_ne_bytes(buf[24..32].try_into().unwrap()),
        exit_signal: u64::from_ne_bytes(buf[32..40].try_into().unwrap()),
        stack: u64::from_ne_bytes(buf[40..48].try_into().unwrap()),
        stack_size: u64::from_ne_bytes(buf[48..56].try_into().unwrap()),
        tls: u64::from_ne_bytes(buf[56..64].try_into().unwrap()),
        set_tid: u64::from_ne_bytes(buf[64..72].try_into().unwrap()),
        set_tid_size: u64::from_ne_bytes(buf[72..80].try_into().unwrap()),
        cgroup: u64::from_ne_bytes(buf[80..88].try_into().unwrap()),
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
