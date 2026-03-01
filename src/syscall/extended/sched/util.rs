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

pub const PRIO_PROCESS: i32 = 0;
pub const PRIO_PGRP: i32 = 1;
pub const PRIO_USER: i32 = 2;

pub fn resolve_pid(pid: i32) -> Option<u32> {
    if pid < 0 {
        return None;
    }

    let target_pid = if pid == 0 {
        crate::process::current_pid().unwrap_or(0)
    } else {
        pid as u32
    };

    if crate::process::is_process_active_by_id(target_pid.into()) {
        Some(target_pid)
    } else {
        None
    }
}

pub fn can_modify_process(target_pid: u32) -> bool {
    let current_pid = crate::process::current_pid().unwrap_or(0);

    if current_pid == target_pid {
        return true;
    }

    true
}

pub fn ok(value: i64) -> SyscallResult {
    SyscallResult { value, capability_consumed: false, audit_required: false }
}
