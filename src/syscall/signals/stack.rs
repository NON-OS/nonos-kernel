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

use super::state::*;
use super::types::*;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

const STACK_T_SIZE: usize = 24;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

/// # Safety
/// Handles sigaltstack syscall with validated user pointers.
/// Uses usercopy for all user space memory access.
pub fn handle_sigaltstack(ss: u64, old_ss: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);
    let mut state = get_signal_state(pid);

    if old_ss != 0 {
        let mut buf = [0u8; STACK_T_SIZE];
        if let Some((base, size)) = state.alt_stack {
            buf[0..8].copy_from_slice(&base.to_ne_bytes());
            buf[8..12].copy_from_slice(&0i32.to_ne_bytes());
            buf[16..24].copy_from_slice(&(size as u64).to_ne_bytes());
        } else {
            buf[0..8].copy_from_slice(&0u64.to_ne_bytes());
            buf[8..12].copy_from_slice(&2i32.to_ne_bytes());
            buf[16..24].copy_from_slice(&0u64.to_ne_bytes());
        }
        if copy_to_user(old_ss, &buf).is_err() {
            return errno(14);
        }
    }

    if ss != 0 {
        let mut buf = [0u8; STACK_T_SIZE];
        if copy_from_user(ss, &mut buf).is_err() {
            return errno(14);
        }

        let ss_sp = u64::from_ne_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
        let ss_flags = i32::from_ne_bytes(buf[8..12].try_into().unwrap_or([0; 4]));
        let ss_size = u64::from_ne_bytes(buf[16..24].try_into().unwrap_or([0; 8]));

        const SS_DISABLE: i32 = 2;
        const MINSIGSTKSZ: u64 = 2048;

        if (ss_flags & SS_DISABLE) != 0 {
            state.alt_stack = None;
        } else {
            if ss_size < MINSIGSTKSZ {
                return errno(12);
            }
            state.alt_stack = Some((ss_sp, ss_size as usize));
        }
    }

    set_signal_state(pid, state);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

/// # Safety
/// Writes siginfo to user space buffer using validated usercopy.
/// Buffer must be at least 128 bytes.
pub fn write_siginfo(addr: u64, info: &PendingSignal) -> Result<(), ()> {
    let mut buf = [0u8; 128];
    buf[0..4].copy_from_slice(&(info.signo as i32).to_ne_bytes());
    buf[4..8].copy_from_slice(&0i32.to_ne_bytes());
    buf[8..12].copy_from_slice(&info.code.to_ne_bytes());
    buf[16..20].copy_from_slice(&info.pid.to_ne_bytes());
    buf[20..24].copy_from_slice(&info.uid.to_ne_bytes());
    copy_to_user(addr, &buf).map_err(|_| ())
}
