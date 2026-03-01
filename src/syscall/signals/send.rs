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
use super::state::SIGNAL_STATE;
use super::delivery::*;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_kill(pid: i64, sig: u64) -> SyscallResult {
    if sig > SIGRTMAX as u64 {
        return errno(22);
    }

    let current_pid = crate::process::current_pid().unwrap_or(0) as i64;

    match pid {
        0 => {
            return send_signal(current_pid as u32, sig as u32);
        }
        -1 => {
            let state_map = SIGNAL_STATE.read();
            for target_pid in state_map.keys() {
                let _ = send_signal(*target_pid, sig as u32);
            }
            return SyscallResult { value: 0, capability_consumed: false, audit_required: true };
        }
        p if p < -1 => {
            let pgid = (-p) as u32;
            return send_signal(pgid, sig as u32);
        }
        p => {
            return send_signal(p as u32, sig as u32);
        }
    }
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

    let sender_pid = crate::process::current_pid().unwrap_or(0);

    let si_code = unsafe { core::ptr::read((info + 8) as *const i32) };
    let si_value = unsafe { core::ptr::read((info + 16) as *const u64) };

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

    let sender_pid = crate::process::current_pid().unwrap_or(0);

    let si_code = unsafe { core::ptr::read((info + 8) as *const i32) };
    let si_value = unsafe { core::ptr::read((info + 16) as *const u64) };

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
