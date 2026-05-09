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

use super::types::*;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

const SIGACTION_SIZE: usize = 32;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn handle_rt_sigaction(sig: u64, act: u64, oldact: u64, sigsetsize: u64) -> SyscallResult {
    let value = crate::process::signal::syscall::sys_rt_sigaction(sig, act, oldact, sigsetsize);
    SyscallResult { value, capability_consumed: false, audit_required: value != 0 }
}

/// # Safety
/// Reads sigaction struct from user space using validated usercopy.
pub fn read_sigaction(addr: u64) -> Result<KernelSigAction, SyscallResult> {
    let mut buf = [0u8; SIGACTION_SIZE];
    if copy_from_user(addr, &mut buf).is_err() {
        return Err(errno(14));
    }

    let handler = u64::from_ne_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let flags = u64::from_ne_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
    let restorer = u64::from_ne_bytes(buf[16..24].try_into().unwrap_or([0; 8]));
    let mask = u64::from_ne_bytes(buf[24..32].try_into().unwrap_or([0; 8]));

    Ok(KernelSigAction { handler, flags, restorer, mask: SigSet(mask) })
}

/// # Safety
/// Writes sigaction struct to user space using validated usercopy.
pub fn write_sigaction(addr: u64, action: &KernelSigAction) -> Result<(), ()> {
    let mut buf = [0u8; SIGACTION_SIZE];
    buf[0..8].copy_from_slice(&action.handler.to_ne_bytes());
    buf[8..16].copy_from_slice(&action.flags.to_ne_bytes());
    buf[16..24].copy_from_slice(&action.restorer.to_ne_bytes());
    buf[24..32].copy_from_slice(&action.mask.0.to_ne_bytes());
    copy_to_user(addr, &buf).map_err(|_| ())
}
