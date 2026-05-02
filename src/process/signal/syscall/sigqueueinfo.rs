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

use super::perm::may_signal;
use crate::process::signal::constants::SIGRTMAX;
use crate::process::signal::send::send_signal_info;
use crate::process::signal::siginfo::{SigCode, SigInfo};
use crate::usercopy::read_user_value;

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const EPERM: i64 = -1;
const ESRCH: i64 = -3;

/// Front of the POSIX `siginfo_t` layout — enough fields for queue
/// origin, value, and the sender's pid/uid. The rest of the 128-byte
/// userspace struct is the union tail, which this syscall does not
/// need to copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct UserSigInfoFront {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad: i32,
    si_pid: i32,
    si_uid: u32,
    si_value: i64,
}

pub fn sys_rt_sigqueueinfo(pid: u64, sig: u64, info: u64) -> i64 {
    if sig < 1 || sig > SIGRTMAX as u64 {
        return EINVAL;
    }
    if info == 0 {
        return EFAULT;
    }
    let target = pid as u32;
    if !may_signal(target) {
        return EPERM;
    }
    let user_info: UserSigInfoFront = match read_user_value(info) {
        Ok(v) => v,
        Err(_) => return EFAULT,
    };
    let signo = sig as u8;
    let our_info = SigInfo {
        signo,
        code: SigCode(user_info.si_code),
        errno: user_info.si_errno,
        pid: user_info.si_pid as u32,
        uid: user_info.si_uid,
        status: 0,
        addr: 0,
        value: user_info.si_value,
        band: 0,
    };
    match send_signal_info(target, signo, our_info) {
        Ok(()) => 0,
        Err(_) => ESRCH,
    }
}
