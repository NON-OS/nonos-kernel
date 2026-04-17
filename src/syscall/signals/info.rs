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

use super::types::PendingSignal;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: i32,
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    pub _pad1: i32,
    pub si_value: u64,
    pub _reserved: [u64; 12],
}

impl SigInfo {
    pub fn new(signo: i32, code: i32) -> Self {
        Self { si_signo: signo, si_code: code, ..Default::default() }
    }

    pub fn from_pending(pending: &PendingSignal) -> Self {
        Self {
            si_signo: pending.signo as i32,
            si_errno: 0,
            si_code: pending.code,
            _pad0: 0,
            si_pid: pending.pid as i32,
            si_uid: pending.uid,
            si_status: 0,
            _pad1: 0,
            si_value: pending.value,
            _reserved: [0; 12],
        }
    }

    pub fn to_pending(&self) -> PendingSignal {
        PendingSignal {
            signo: self.si_signo as u32,
            code: self.si_code,
            pid: self.si_pid as u32,
            uid: self.si_uid,
            value: self.si_value,
            timestamp: crate::time::timestamp_millis(),
        }
    }

    pub fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

pub fn copy_siginfo_to_user(dest: u64, info: &SigInfo) -> Result<(), i32> {
    if dest == 0 { return Err(-14); }
    if crate::usercopy::validate_user_write(dest, SigInfo::size()).is_err() { return Err(-14); }
    let src = info as *const SigInfo as *const u8;
    let bytes = unsafe { core::slice::from_raw_parts(src, SigInfo::size()) };
    if crate::usercopy::copy_to_user(dest, bytes).is_err() { return Err(-14); }
    Ok(())
}

pub fn copy_siginfo_from_user(src: u64) -> Result<SigInfo, i32> {
    if src == 0 { return Err(-14); }
    if crate::usercopy::validate_user_read(src, SigInfo::size()).is_err() { return Err(-14); }
    let mut info = SigInfo::default();
    let dst = &mut info as *mut SigInfo as *mut u8;
    let bytes = unsafe { core::slice::from_raw_parts_mut(dst, SigInfo::size()) };
    if crate::usercopy::copy_from_user(src, bytes).is_err() { return Err(-14); }
    Ok(info)
}

pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 128;
pub const SI_QUEUE: i32 = -1;
pub const SI_TIMER: i32 = -2;
pub const SI_MESGQ: i32 = -3;
pub const SI_ASYNCIO: i32 = -4;
pub const SI_SIGIO: i32 = -5;
pub const SI_TKILL: i32 = -6;

pub fn siginfo_is_from_kernel(code: i32) -> bool {
    code == SI_KERNEL
}

pub fn siginfo_is_from_user(code: i32) -> bool {
    code == SI_USER || code == SI_TKILL
}

pub fn siginfo_is_queued(code: i32) -> bool {
    code == SI_QUEUE
}
