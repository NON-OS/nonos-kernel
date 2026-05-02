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
use super::delivery::*;
use super::state::SIGNAL_STATE;
use super::types::*;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

const SIGINFO_MIN_SIZE: usize = 24;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_kill(pid: i64, sig: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_kill(pid, sig);
    SyscallResult { value, capability_consumed: false, audit_required: true }
}

pub fn handle_tgkill(tgid: u64, tid: u64, sig: u64) -> SyscallResult {
    if tgid != tid {
        return errno(3);
    }

    send_signal(tid as u32, sig as u32)
}

pub fn handle_tkill(tid: u64, sig: u64) -> SyscallResult {
    send_signal(tid as u32, sig as u32)
}

pub fn handle_rt_sigqueueinfo(pid: u64, sig: u64, info: u64) -> SyscallResult {
    if sig < 1 || sig > SIGRTMAX as u64 {
        return errno(22);
    }

    if info == 0 {
        return errno(14);
    }

    let mut buf = [0u8; SIGINFO_MIN_SIZE];
    if copy_from_user(info, &mut buf).is_err() {
        return errno(14);
    }

    let sender_pid = crate::process::current_pid().unwrap_or(0);
    let si_code = i32::from_ne_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
    let si_value = u64::from_ne_bytes(buf[16..24].try_into().unwrap_or([0; 8]));

    let pending = PendingSignal {
        signo: sig as u32,
        code: si_code,
        pid: sender_pid,
        uid: 0,
        value: si_value,
        timestamp: crate::time::timestamp_millis(),
    };

    queue_signal(pid as u32, pending)
}

pub fn handle_rt_tgsigqueueinfo(tgid: u64, tid: u64, sig: u64, info: u64) -> SyscallResult {
    if sig < 1 || sig > SIGRTMAX as u64 {
        return errno(22);
    }

    if info == 0 {
        return errno(14);
    }

    if tgid != tid {
        return errno(3);
    }

    let mut buf = [0u8; SIGINFO_MIN_SIZE];
    if copy_from_user(info, &mut buf).is_err() {
        return errno(14);
    }

    let sender_pid = crate::process::current_pid().unwrap_or(0);
    let si_code = i32::from_ne_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
    let si_value = u64::from_ne_bytes(buf[16..24].try_into().unwrap_or([0; 8]));

    let pending = PendingSignal {
        signo: sig as u32,
        code: si_code,
        pid: sender_pid,
        uid: 0,
        value: si_value,
        timestamp: crate::time::timestamp_millis(),
    };

    queue_signal(tid as u32, pending)
}
