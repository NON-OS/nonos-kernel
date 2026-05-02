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

use super::constants::*;
use super::state::*;
use super::types::*;
use crate::syscall::SyscallResult;
use crate::usercopy::read_user_value;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_rt_sigreturn() -> SyscallResult {
    crate::process::signal::delivery::sigreturn_current()
}

pub fn handle_rt_sigsuspend(mask: u64, sigsetsize: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigsuspend(mask, sigsetsize);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}

pub fn handle_pause() -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    loop {
        let state = get_signal_state(pid);

        let deliverable = state.pending.0 & !state.blocked.0;
        if deliverable != 0 {
            break;
        }

        crate::sched::yield_cpu();
    }

    errno(4)
}
