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
use super::constants::*;
use super::types::*;
use super::state::*;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64) -> SyscallResult {
    if sigsetsize != 8 {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);
    let mut state = get_signal_state(pid);

    if oldset != 0 {
        unsafe {
            core::ptr::write(oldset as *mut u64, state.blocked.0);
        }
    }

    if set != 0 {
        let new_set = unsafe { core::ptr::read(set as *const u64) };
        let new_sigset = SigSet(new_set);

        match how as u32 {
            SIG_BLOCK => {
                state.blocked.0 |= new_sigset.0;
            }
            SIG_UNBLOCK => {
                state.blocked.0 &= !new_sigset.0;
            }
            SIG_SETMASK => {
                state.blocked.0 = new_sigset.0;
            }
            _ => return errno(22),
        }

        state.blocked.remove(SIGKILL);
        state.blocked.remove(SIGSTOP);
    }

    set_signal_state(pid, state);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_rt_sigpending(set: u64, sigsetsize: u64) -> SyscallResult {
    if sigsetsize != 8 {
        return errno(22);
    }

    if set == 0 {
        return errno(14);
    }

    let pid = crate::process::current_pid().unwrap_or(0);
    let state = get_signal_state(pid);

    unsafe {
        core::ptr::write(set as *mut u64, state.pending.0);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
