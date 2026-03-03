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
    NICE_MIN, NICE_MAX,
    IOPRIO_CLASS_NONE, IOPRIO_CLASS_RT, IOPRIO_CLASS_IDLE,
    IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
    decode_ioprio_class, decode_ioprio_level,
};
use crate::syscall::extended::errno;
use super::util::{PRIO_PROCESS, PRIO_PGRP, PRIO_USER, can_modify_process, ok};

pub fn handle_getpriority(which: i32, who: u32) -> SyscallResult {
    if which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER {
        return errno(22);
    }

    let target_pid = match which {
        PRIO_PROCESS => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who
            }
        }
        PRIO_PGRP => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who
            }
        }
        PRIO_USER => {
            crate::process::current_pid().unwrap_or(0)
        }
        _ => return errno(22),
    };

    if !crate::process::is_process_active_by_id(target_pid.into()) {
        return errno(3);
    }

    let nice = policy::get_nice(target_pid);

    ok(20 - nice as i64)
}

pub fn handle_setpriority(which: i32, who: u32, prio: i32) -> SyscallResult {
    if which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER {
        return errno(22);
    }

    let target_pid = match which {
        PRIO_PROCESS => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who
            }
        }
        PRIO_PGRP => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who
            }
        }
        PRIO_USER => {
            crate::process::current_pid().unwrap_or(0)
        }
        _ => return errno(22),
    };

    if !crate::process::is_process_active_by_id(target_pid.into()) {
        return errno(3);
    }

    if !can_modify_process(target_pid) {
        return errno(1);
    }

    let nice = prio.max(NICE_MIN).min(NICE_MAX);

    if let Err(_) = policy::set_nice(target_pid, nice) {
        return errno(1);
    }

    ok(0)
}

pub fn handle_ioprio_set(which: i32, who: i32, ioprio: i32) -> SyscallResult {
    if which != IOPRIO_WHO_PROCESS && which != IOPRIO_WHO_PGRP && which != IOPRIO_WHO_USER {
        return errno(22);
    }

    let target_pid = match which {
        IOPRIO_WHO_PROCESS => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who as u32
            }
        }
        IOPRIO_WHO_PGRP => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who as u32
            }
        }
        IOPRIO_WHO_USER => {
            crate::process::current_pid().unwrap_or(0)
        }
        _ => return errno(22),
    };

    if !crate::process::is_process_active_by_id(target_pid.into()) {
        return errno(3);
    }

    if !can_modify_process(target_pid) {
        return errno(1);
    }

    let class = decode_ioprio_class(ioprio as u16);
    let level = decode_ioprio_level(ioprio as u16);

    if class < IOPRIO_CLASS_NONE || class > IOPRIO_CLASS_IDLE {
        return errno(22);
    }

    if class == IOPRIO_CLASS_RT && level > 7 {
        return errno(22);
    }

    if let Err(_) = policy::set_ioprio(target_pid, ioprio as u16) {
        return errno(22);
    }

    ok(0)
}

pub fn handle_ioprio_get(which: i32, who: i32) -> SyscallResult {
    if which != IOPRIO_WHO_PROCESS && which != IOPRIO_WHO_PGRP && which != IOPRIO_WHO_USER {
        return errno(22);
    }

    let target_pid = match which {
        IOPRIO_WHO_PROCESS => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who as u32
            }
        }
        IOPRIO_WHO_PGRP => {
            if who == 0 {
                crate::process::current_pid().unwrap_or(0)
            } else {
                who as u32
            }
        }
        IOPRIO_WHO_USER => {
            crate::process::current_pid().unwrap_or(0)
        }
        _ => return errno(22),
    };

    if !crate::process::is_process_active_by_id(target_pid.into()) {
        return errno(3);
    }

    let ioprio = policy::get_ioprio(target_pid);
    ok(ioprio as i64)
}

pub fn handle_sched_yield() -> SyscallResult {
    ok(0)
}
