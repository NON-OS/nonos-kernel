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

use core::sync::atomic::Ordering;

use super::perm::may_signal;
use crate::process::signal::constants::SIGRTMAX;
use crate::process::signal::send::{send_signal, send_signal_to_group};
use crate::process::{current_pid, with_process};

const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const ESRCH: i64 = -3;

pub fn sys_kill(pid: i64, sig: u64) -> i64 {
    if sig > SIGRTMAX as u64 {
        return EINVAL;
    }

    match pid {
        p if p > 0 => kill_pid(p as u32, sig as u32),
        0 => kill_caller_pgrp(sig as u32),
        // POSIX kill(-1, ...) broadcasts to every process the caller
        // can signal except init. Implementing that requires a real
        // process-iteration + per-target permission pass plus an
        // explicit init-pid filter; none of that is in this commit, so
        // the call is rejected with EINVAL rather than silently sent
        // to one process.
        -1 => EINVAL,
        p => {
            let pgid = (-p) as i32;
            match send_signal_to_group(pgid, sig as u32) {
                Ok(()) => 0,
                Err(_) => ESRCH,
            }
        }
    }
}

fn kill_pid(target: u32, sig: u32) -> i64 {
    if !may_signal(target) {
        return EPERM;
    }
    if sig == 0 {
        return if with_process(target, |_| ()).is_some() { 0 } else { ESRCH };
    }
    match send_signal(target, sig) {
        Ok(()) => 0,
        Err(_) => ESRCH,
    }
}

fn kill_caller_pgrp(sig: u32) -> i64 {
    let caller = current_pid().unwrap_or(0);
    let pgid = match with_process(caller, |pcb| pcb.pgid.load(Ordering::Acquire)) {
        Some(g) if g != 0 => g,
        _ => return ESRCH,
    };
    match send_signal_to_group(pgid as i32, sig) {
        Ok(()) => 0,
        Err(_) => ESRCH,
    }
}
