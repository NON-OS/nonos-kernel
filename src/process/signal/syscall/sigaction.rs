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

use crate::process::signal::constants::{SIGKILL, SIGRTMAX, SIGSTOP};
use crate::process::signal::sigaction::{KernelSigaction, Sigaction, SigactionFlags};
use crate::process::{current_pid, with_process_mut};
use crate::usercopy::{read_user_value, write_user_value};

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const ESRCH: i64 = -3;

/// Only `SA_RESTORER` is honored at install time. Every other
/// `SA_*` flag would have observable behavior the delivery path does
/// not implement yet, so they are refused with `-EINVAL` rather than
/// stored and silently ignored.
pub fn sys_rt_sigaction(sig: u64, act: u64, oldact: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if sig < 1 || sig > SIGRTMAX as u64 {
        return EINVAL;
    }
    let signo = sig as u8;
    if act != 0 && (signo == SIGKILL || signo == SIGSTOP) {
        return EINVAL;
    }
    let pid = current_pid().unwrap_or(0);

    if oldact != 0 {
        let current = match with_process_mut(pid, |pcb| {
            KernelSigaction::from(pcb.signals.lock().get_action(signo))
        }) {
            Some(c) => c,
            None => return ESRCH,
        };
        if write_user_value(oldact, &current).is_err() {
            return EFAULT;
        }
    }

    if act != 0 {
        let new: KernelSigaction = match read_user_value(act) {
            Ok(v) => v,
            Err(_) => return EFAULT,
        };
        let flags = SigactionFlags::from_bits_truncate(new.sa_flags as u32);
        if flags.difference(SigactionFlags::RESTORER) != SigactionFlags::empty() {
            return EINVAL;
        }
        let action = Sigaction::from(new);
        if with_process_mut(pid, |pcb| pcb.signals.lock().set_action(signo, action)).is_none() {
            return ESRCH;
        }
    }

    0
}
