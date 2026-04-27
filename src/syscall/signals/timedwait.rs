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

use super::stack::write_siginfo;
use super::state::*;
use super::types::*;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_to_user, read_user_value};

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_rt_sigtimedwait(set: u64, info: u64, timeout: u64, sigsetsize: u64) -> SyscallResult {
    if sigsetsize != 8 || set == 0 {
        return errno(22);
    }

    let set_val: u64 = match read_user_value(set) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let wait_set = SigSet(set_val);
    let pid = crate::process::current_pid().unwrap_or(0);

    let deadline = if timeout != 0 {
        let tv_sec: i64 = match read_user_value(timeout) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let timeout_nsec = match timeout.checked_add(8) {
            Some(v) => v,
            None => return errno(14),
        };
        let tv_nsec: i64 = match read_user_value(timeout_nsec) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let sec_ms = (tv_sec as u64).saturating_mul(1000);
        let timeout_ms = sec_ms.saturating_add((tv_nsec as u64) / 1_000_000);
        Some(crate::time::timestamp_millis().saturating_add(timeout_ms))
    } else {
        None
    };

    loop {
        let mut state = get_signal_state(pid);

        let deliverable = state.pending.0 & wait_set.0;

        if deliverable != 0 {
            let signo = (deliverable.trailing_zeros() + 1) as u32;

            state.pending.remove(signo);

            let mut siginfo: Option<PendingSignal> = None;
            state.pending_queue.retain(|s| {
                if s.signo == signo && siginfo.is_none() {
                    siginfo = Some(s.clone());
                    false
                } else {
                    true
                }
            });

            set_signal_state(pid, state);

            if info != 0 {
                if let Some(si) = siginfo {
                    if write_siginfo(info, &si).is_err() {
                        return errno(14);
                    }
                } else {
                    let zero_buf = [0u8; 128];
                    if copy_to_user(info, &zero_buf).is_err() {
                        return errno(14);
                    }
                }
            }

            return SyscallResult {
                value: signo as i64,
                capability_consumed: false,
                audit_required: false,
            };
        }

        if let Some(deadline) = deadline {
            if crate::time::timestamp_millis() >= deadline {
                return errno(11);
            }
        }

        crate::sched::yield_cpu();
    }
}
