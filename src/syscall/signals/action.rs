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

pub fn handle_rt_sigaction(sig: u64, act: u64, oldact: u64, sigsetsize: u64) -> SyscallResult {
    if sig < 1 || sig > SIGRTMAX as u64 {
        return errno(22);
    }

    let sig = sig as u32;

    if sig == SIGKILL || sig == SIGSTOP {
        return errno(22);
    }

    if sigsetsize != 8 {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);
    let mut state = get_signal_state(pid);

    if oldact != 0 {
        let old = &state.actions[sig as usize];
        write_sigaction(oldact, old);
    }

    if act != 0 {
        let new_action = match read_sigaction(act) {
            Ok(action) => action,
            Err(e) => return e,
        };
        state.actions[sig as usize] = new_action;
    }

    set_signal_state(pid, state);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn read_sigaction(addr: u64) -> Result<KernelSigAction, SyscallResult> {
    let handler = unsafe { core::ptr::read(addr as *const u64) };
    let flags = unsafe { core::ptr::read((addr + 8) as *const u64) };
    let restorer = unsafe { core::ptr::read((addr + 16) as *const u64) };
    let mask = unsafe { core::ptr::read((addr + 24) as *const u64) };

    Ok(KernelSigAction {
        handler,
        flags,
        restorer,
        mask: SigSet(mask),
    })
}

pub fn write_sigaction(addr: u64, action: &KernelSigAction) {
    unsafe {
        core::ptr::write(addr as *mut u64, action.handler);
        core::ptr::write((addr + 8) as *mut u64, action.flags);
        core::ptr::write((addr + 16) as *mut u64, action.restorer);
        core::ptr::write((addr + 24) as *mut u64, action.mask.0);
    }
}
