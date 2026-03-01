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

pub fn handle_getppid() -> SyscallResult {
    let ppid = 1u32;
    SyscallResult { value: ppid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_getuid() -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_geteuid() -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_getgid() -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_getegid() -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_gettid() -> SyscallResult {
    let tid = crate::process::current_pid().unwrap_or(0);
    SyscallResult { value: tid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_getpid_extended() -> SyscallResult {
    if let Some(pcb) = crate::process::current_process() {
        let tgid = pcb.thread_group_id();
        SyscallResult { value: tgid as i64, capability_consumed: false, audit_required: false }
    } else {
        SyscallResult { value: 0, capability_consumed: false, audit_required: false }
    }
}

pub fn handle_getpgrp() -> SyscallResult {
    let pgrp = crate::process::current_process()
        .map(|p| p.process_group())
        .unwrap_or(1);
    SyscallResult { value: pgrp as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_getpgid(pid: i32) -> SyscallResult {
    if pid == 0 {
        return handle_getpgrp();
    }

    let pgrp = crate::process::get_process_table()
        .get_process(pid as u32)
        .map(|p| p.process_group())
        .unwrap_or(0);

    if pgrp == 0 {
        return errno(3);
    }

    SyscallResult { value: pgrp as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_setpgid(pid: i32, pgid: i32) -> SyscallResult {
    let target_pid = if pid == 0 {
        crate::process::current_pid().unwrap_or(1) as i32
    } else {
        pid
    };

    let target_pgid = if pgid == 0 {
        target_pid as u32
    } else {
        pgid as u32
    };

    match crate::process::get_process_table().set_process_group(target_pid as u32, target_pgid) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(3),
    }
}

pub fn handle_getsid(pid: i32) -> SyscallResult {
    let target_pid = if pid == 0 {
        crate::process::current_pid().unwrap_or(1) as i32
    } else {
        pid
    };

    let sid = crate::process::get_process_table()
        .get_process(target_pid as u32)
        .map(|p| p.session_id())
        .unwrap_or(0);

    if sid == 0 {
        return errno(3);
    }

    SyscallResult { value: sid as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_setsid() -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(1);

    match crate::process::get_process_table().set_session_leader(pid) {
        Ok(()) => SyscallResult { value: pid as i64, capability_consumed: false, audit_required: true },
        Err(_) => errno(1),
    }
}
