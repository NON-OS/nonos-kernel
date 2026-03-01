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
    LinuxSchedAttr,
    SCHED_NORMAL, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE,
    SCHED_PRIORITY_MIN, SCHED_PRIORITY_MAX, NICE_MIN, NICE_MAX,
};
use crate::syscall::extended::errno;
use super::util::{resolve_pid, can_modify_process, ok};

pub fn handle_sched_setattr(pid: i32, attr_ptr: u64, flags: u32) -> SyscallResult {
    if attr_ptr == 0 {
        return errno(14);
    }

    if flags != 0 {
        return errno(22);
    }

    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };

    if !can_modify_process(target_pid) {
        return errno(1);
    }

    let linux_attr = unsafe {
        core::ptr::read(attr_ptr as *const LinuxSchedAttr)
    };

    if (linux_attr.size as usize) < core::mem::size_of::<LinuxSchedAttr>() {
        return errno(22);
    }

    let sched_policy = linux_attr.sched_policy as i32;
    match sched_policy {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            if linux_attr.sched_priority != 0 {
                return errno(22);
            }
            if linux_attr.sched_nice < NICE_MIN || linux_attr.sched_nice > NICE_MAX {
                return errno(22);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if linux_attr.sched_priority < SCHED_PRIORITY_MIN ||
               linux_attr.sched_priority > SCHED_PRIORITY_MAX {
                return errno(22);
            }
        }
        SCHED_DEADLINE => {
            if linux_attr.sched_runtime == 0 ||
               linux_attr.sched_deadline == 0 ||
               linux_attr.sched_period == 0 {
                return errno(22);
            }
            if linux_attr.sched_runtime > linux_attr.sched_deadline ||
               linux_attr.sched_deadline > linux_attr.sched_period {
                return errno(22);
            }
        }
        _ => return errno(22),
    }

    let mut internal_attr = policy::get_sched_attr(target_pid);
    internal_attr.policy = sched_policy;
    internal_attr.rt_priority = linux_attr.sched_priority;
    internal_attr.nice = linux_attr.sched_nice;
    internal_attr.flags = linux_attr.sched_flags;
    internal_attr.runtime = linux_attr.sched_runtime;
    internal_attr.deadline = linux_attr.sched_deadline;
    internal_attr.period = linux_attr.sched_period;

    policy::set_sched_attr(target_pid, internal_attr);

    ok(0)
}

pub fn handle_sched_getattr(pid: i32, attr_ptr: u64, size: u32, flags: u32) -> SyscallResult {
    if attr_ptr == 0 {
        return errno(14);
    }

    if flags != 0 {
        return errno(22);
    }

    if (size as usize) < core::mem::size_of::<LinuxSchedAttr>() {
        return errno(22);
    }

    let target_pid = match resolve_pid(pid) {
        Some(p) => p,
        None => return errno(3),
    };

    let internal_attr = policy::get_sched_attr(target_pid);

    let linux_attr = LinuxSchedAttr {
        size: core::mem::size_of::<LinuxSchedAttr>() as u32,
        sched_policy: internal_attr.policy as u32,
        sched_flags: internal_attr.flags,
        sched_nice: internal_attr.nice,
        sched_priority: internal_attr.rt_priority,
        sched_runtime: internal_attr.runtime,
        sched_deadline: internal_attr.deadline,
        sched_period: internal_attr.period,
        sched_util_min: 0,
        sched_util_max: 1024,
    };

    unsafe {
        core::ptr::write(attr_ptr as *mut LinuxSchedAttr, linux_attr);
    }

    ok(0)
}
