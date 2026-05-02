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

use crate::process::signal::constants::{SIGKILL, SIGSTOP};
use crate::process::{current_pid, with_process, with_process_mut};
use crate::usercopy::read_user_value;

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const EINTR: i64 = -4;
const ESRCH: i64 = -3;

const UNCATCHABLE: u64 = (1u64 << SIGKILL) | (1u64 << SIGSTOP);

/// POSIX sigsuspend: install the suspended mask, wait for any
/// deliverable signal, and return EINTR with the original mask saved
/// for the sigreturn path to restore after the handler runs. The wait
/// is a `yield_now` loop — there is no signal-driven wakeup primitive
/// in the scheduler yet, so this is cooperative and busy-ish on a CPU
/// that has nothing else to run.
pub fn sys_rt_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let user_mask: u64 = match read_user_value(mask_ptr) {
        Ok(v) => v,
        Err(_) => return EFAULT,
    };
    let suspend_mask = user_mask & !UNCATCHABLE;
    let pid = current_pid().unwrap_or(0);

    let installed = with_process_mut(pid, |pcb| {
        let mut sigs = pcb.signals.lock();
        sigs.save_blocked_for_suspend();
        sigs.set_blocked_mask(suspend_mask);
    });
    if installed.is_none() {
        return ESRCH;
    }

    loop {
        let deliverable = with_process(pid, |pcb| pcb.signals.lock().has_pending_signals())
            .unwrap_or(false);
        if deliverable {
            break;
        }
        crate::sched::yield_now();
    }

    EINTR
}
