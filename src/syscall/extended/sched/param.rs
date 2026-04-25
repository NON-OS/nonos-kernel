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

use super::util::{can_modify_process, ok, resolve_pid};
use crate::process::scheduler::{
    self as policy, SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL,
    SCHED_PRIORITY_MAX, SCHED_PRIORITY_MIN, SCHED_RR,
};
use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_sched_setparam(pid: i32, param: u64) -> SyscallResult {
    if param == 0 {
        return errno(14);
    }
    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };
    if !can_modify_process(target_pid) {
        return errno(1);
    }
    let priority: i32 = match read_user_value(param) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let current_policy = policy::get_policy(target_pid);
    match current_policy {
        SCHED_FIFO | SCHED_RR => {
            if priority < SCHED_PRIORITY_MIN || priority > SCHED_PRIORITY_MAX {
                return errno(22);
            }
        }
        _ => {
            if priority != 0 {
                return errno(22);
            }
        }
    }
    if policy::set_priority(target_pid, priority).is_err() {
        return errno(22);
    }
    ok(0)
}

pub fn handle_sched_getparam(pid: i32, param: u64) -> SyscallResult {
    if param == 0 {
        return errno(14);
    }
    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };
    let priority = policy::get_priority(target_pid);
    if write_user_value(param, &priority).is_err() {
        return errno(14);
    }
    ok(0)
}

pub fn handle_sched_setscheduler(pid: i32, sched_policy: i32, param: u64) -> SyscallResult {
    if param == 0 {
        return errno(14);
    }
    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };
    if !can_modify_process(target_pid) {
        return errno(1);
    }
    match sched_policy {
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE => {}
        SCHED_DEADLINE => return errno(22),
        _ => return errno(22),
    }
    let priority: i32 = match read_user_value(param) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if policy::set_policy(target_pid, sched_policy, priority).is_err() {
        return errno(22);
    }
    ok(sched_policy as i64)
}

pub fn handle_sched_getscheduler(pid: i32) -> SyscallResult {
    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };
    ok(policy::get_policy(target_pid) as i64)
}

pub fn handle_sched_get_priority_max(sched_policy: i32) -> SyscallResult {
    match sched_policy {
        SCHED_FIFO | SCHED_RR => ok(SCHED_PRIORITY_MAX as i64),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => ok(0),
        _ => errno(22),
    }
}

pub fn handle_sched_get_priority_min(sched_policy: i32) -> SyscallResult {
    match sched_policy {
        SCHED_FIFO | SCHED_RR => ok(SCHED_PRIORITY_MIN as i64),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => ok(0),
        _ => errno(22),
    }
}
