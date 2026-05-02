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

use super::info::SigInfo;
use crate::process::signal::constants::{SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGIO, SIGSEGV, SIGTRAP};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelSigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad: i32,
    pub _data: SigInfoData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SigInfoData {
    pub _pad: [i32; 28],
    pub _kill: SigInfoKill,
    pub _timer: SigInfoTimer,
    pub _rt: SigInfoRt,
    pub _sigchld: SigInfoChild,
    pub _sigfault: SigInfoFault,
    pub _sigpoll: SigInfoPoll,
    pub _sigsys: SigInfoSys,
}

impl core::fmt::Debug for SigInfoData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigInfoData").finish()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoKill {
    pub si_pid: i32,
    pub si_uid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoTimer {
    pub si_tid: i32,
    pub si_overrun: i32,
    pub si_sigval: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoRt {
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_sigval: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoChild {
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    pub si_utime: i64,
    pub si_stime: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoFault {
    pub si_addr: u64,
    pub si_addr_lsb: i16,
    pub _pad: [u8; 6],
    pub si_lower: u64,
    pub si_upper: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoPoll {
    pub si_band: i64,
    pub si_fd: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigInfoSys {
    pub si_call_addr: u64,
    pub si_syscall: i32,
    pub si_arch: u32,
}

impl From<&SigInfo> for KernelSigInfo {
    fn from(info: &SigInfo) -> Self {
        let mut ksi = Self {
            si_signo: info.signo as i32,
            si_errno: info.errno,
            si_code: info.code.0,
            _pad: 0,
            _data: SigInfoData { _pad: [0; 28] },
        };
        match info.signo {
            SIGCHLD => {
                ksi._data._sigchld = SigInfoChild {
                    si_pid: info.pid as i32,
                    si_uid: info.uid,
                    si_status: info.status,
                    si_utime: 0,
                    si_stime: 0,
                };
            }
            SIGSEGV | SIGBUS | SIGFPE | SIGILL | SIGTRAP => {
                ksi._data._sigfault = SigInfoFault {
                    si_addr: info.addr,
                    si_addr_lsb: 0,
                    _pad: [0; 6],
                    si_lower: 0,
                    si_upper: 0,
                };
            }
            SIGIO => {
                ksi._data._sigpoll =
                    SigInfoPoll { si_band: info.band, si_fd: info.pid as i32 };
            }
            _ => {
                ksi._data._kill =
                    SigInfoKill { si_pid: info.pid as i32, si_uid: info.uid };
            }
        }
        ksi
    }
}
