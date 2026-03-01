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
use crate::process::scheduler::{
    self as policy,
    SchedParam,
    SCHED_NORMAL, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
    SCHED_PRIORITY_MIN, SCHED_PRIORITY_MAX,
};
use crate::syscall::extended::errno;
use super::util::{resolve_pid, can_modify_process, ok};

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

    let sched_param = unsafe {
        core::ptr::read(param as *const SchedParam)
    };

    let current_policy = policy::get_policy(target_pid);

    match current_policy {
        SCHED_FIFO | SCHED_RR => {
            if sched_param.sched_priority < SCHED_PRIORITY_MIN ||
               sched_param.sched_priority > SCHED_PRIORITY_MAX {
                return errno(22);
            }
        }
        _ => {
            if sched_param.sched_priority != 0 {
                return errno(22);
            }
        }
    }

    if let Err(_) = policy::set_priority(target_pid, sched_param.sched_priority) {
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

    unsafe {
        core::ptr::write(param as *mut SchedParam, SchedParam {
            sched_priority: priority,
        });
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
        SCHED_DEADLINE => {
            return errno(22);
        }
        _ => return errno(22),
    }

    let sched_param = unsafe {
        core::ptr::read(param as *const SchedParam)
    };

    if let Err(_) = policy::set_policy(target_pid, sched_policy, sched_param.sched_priority) {
        return errno(22);
    }

    ok(sched_policy as i64)
}

pub fn handle_sched_getscheduler(pid: i32) -> SyscallResult {
    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };

    let sched_policy = policy::get_policy(target_pid);
    ok(sched_policy as i64)
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

pub fn handle_sched_rr_get_interval(pid: i32, tp: u64) -> SyscallResult {
    if tp == 0 {
        return errno(14);
    }

    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };

    let attr = policy::get_sched_attr(target_pid);
    let timeslice_ms = attr.get_timeslice();

    unsafe {
        let ptr = tp as *mut [i64; 2];
        (*ptr)[0] = (timeslice_ms / 1000) as i64;
        (*ptr)[1] = ((timeslice_ms % 1000) * 1_000_000) as i64;
    }

    ok(0)
}
