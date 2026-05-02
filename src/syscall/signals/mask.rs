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
use crate::usercopy::{read_user_value, write_user_value};

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigprocmask(how, set, oldset, sigsetsize);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
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

    if write_user_value(set, &state.pending.0).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
