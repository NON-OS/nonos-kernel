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
use super::types::*;
use super::state::*;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_sigaltstack(ss: u64, old_ss: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);
    let mut state = get_signal_state(pid);

    if old_ss != 0 {
        if let Some((base, size)) = state.alt_stack {
            unsafe {
                core::ptr::write(old_ss as *mut u64, base);
                core::ptr::write((old_ss + 8) as *mut i32, 0);
                core::ptr::write((old_ss + 16) as *mut u64, size as u64);
            }
        } else {
            unsafe {
                core::ptr::write(old_ss as *mut u64, 0);
                core::ptr::write((old_ss + 8) as *mut i32, 2);
                core::ptr::write((old_ss + 16) as *mut u64, 0);
            }
        }
    }

    if ss != 0 {
        let ss_sp = unsafe { core::ptr::read(ss as *const u64) };
        let ss_flags = unsafe { core::ptr::read((ss + 8) as *const i32) };
        let ss_size = unsafe { core::ptr::read((ss + 16) as *const u64) };

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

pub fn write_siginfo(addr: u64, info: &PendingSignal) {
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, 128);
        core::ptr::write(addr as *mut i32, info.signo as i32);
        core::ptr::write((addr + 4) as *mut i32, 0);
        core::ptr::write((addr + 8) as *mut i32, info.code);
        core::ptr::write((addr + 16) as *mut u32, info.pid);
        core::ptr::write((addr + 20) as *mut u32, info.uid);
    }
}
