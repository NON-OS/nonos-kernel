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
use crate::process::{current_pid, with_process_mut};
use crate::usercopy::{read_user_value, write_user_value};

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const ESRCH: i64 = -3;

const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

const UNCATCHABLE: u64 = (1u64 << SIGKILL) | (1u64 << SIGSTOP);

pub fn sys_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let pid = current_pid().unwrap_or(0);

    if oldset != 0 {
        let current = match with_process_mut(pid, |pcb| pcb.signals.lock().get_blocked_mask()) {
            Some(v) => v,
            None => return ESRCH,
        };
        if write_user_value(oldset, &current).is_err() {
            return EFAULT;
        }
    }

    if set != 0 {
        let new_set: u64 = match read_user_value(set) {
            Ok(v) => v,
            Err(_) => return EFAULT,
        };
        let updated = match with_process_mut(pid, |pcb| {
            let sigs = pcb.signals.lock();
            let cur = sigs.get_blocked_mask();
            let next = match how {
                SIG_BLOCK => cur | new_set,
                SIG_UNBLOCK => cur & !new_set,
                SIG_SETMASK => new_set,
                _ => return Err(EINVAL),
            };
            sigs.set_blocked_mask(next & !UNCATCHABLE);
            Ok(())
        }) {
            Some(r) => r,
            None => return ESRCH,
        };
        if let Err(e) = updated {
            return e;
        }
    }

    0
}
