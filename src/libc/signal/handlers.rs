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

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGABRT: i32 = 6;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGSEGV: i32 = 11;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGUSR1: i32 = 10;
pub const SIGUSR2: i32 = 12;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const NSIG: usize = 64;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
pub const SIG_ERR: usize = usize::MAX;
pub const SA_NOCLDSTOP: u64 = 1;
pub const SA_NOCLDWAIT: u64 = 2;
pub const SA_SIGINFO: u64 = 4;
pub const SA_RESTORER: u64 = 0x04000000;
pub const SA_RESTART: u64 = 0x10000000;

pub type SigHandler = extern "C" fn(i32);
pub type SigActionFn = extern "C" fn(i32, *mut SigInfo, *mut u8);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sigset {
    pub bits: [u64; 1],
}
#[repr(C)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad: [i32; 29],
}
#[repr(C)]
pub struct SigAction {
    pub sa_handler: usize,
    pub sa_flags: u64,
    pub sa_restorer: usize,
    pub sa_mask: Sigset,
}

impl Default for Sigset {
    fn default() -> Self {
        Self { bits: [0] }
    }
}
impl Default for SigAction {
    fn default() -> Self {
        Self { sa_handler: SIG_DFL, sa_flags: 0, sa_restorer: 0, sa_mask: Sigset::default() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal(signum: i32, handler: SigHandler) -> usize {
    let mut act = SigAction::default();
    act.sa_handler = handler as usize;
    act.sa_flags = SA_RESTART;
    let mut old = SigAction::default();
    if sigaction(signum, &act, &mut old) < 0 {
        return SIG_ERR;
    }
    old.sa_handler
}

#[no_mangle]
pub unsafe extern "C" fn sigaction(
    signum: i32,
    act: *const SigAction,
    oldact: *mut SigAction,
) -> i32 {
    let ret = crate::syscall::sys_rt_sigaction(signum, act as u64, oldact as u64, 8);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn raise(sig: i32) -> i32 {
    kill(crate::libc::unistd::getpid(), sig)
}

#[no_mangle]
pub unsafe extern "C" fn kill(pid: i32, sig: i32) -> i32 {
    let ret = crate::syscall::sys_kill(pid as i64, sig);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigprocmask(how: i32, set: *const Sigset, oldset: *mut Sigset) -> i32 {
    let ret = crate::syscall::sys_rt_sigprocmask(how, set as u64, oldset as u64, 8);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigemptyset(set: *mut Sigset) -> i32 {
    if set.is_null() {
        return -1;
    }
    (*set).bits[0] = 0;
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigfillset(set: *mut Sigset) -> i32 {
    if set.is_null() {
        return -1;
    }
    (*set).bits[0] = !0;
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigaddset(set: *mut Sigset, signum: i32) -> i32 {
    if set.is_null() || signum < 1 || signum >= NSIG as i32 {
        return -1;
    }
    (*set).bits[0] |= 1u64 << (signum - 1);
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigdelset(set: *mut Sigset, signum: i32) -> i32 {
    if set.is_null() || signum < 1 || signum >= NSIG as i32 {
        return -1;
    }
    (*set).bits[0] &= !(1u64 << (signum - 1));
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigismember(set: *const Sigset, signum: i32) -> i32 {
    if set.is_null() || signum < 1 || signum >= NSIG as i32 {
        return -1;
    }
    if ((*set).bits[0] & (1u64 << (signum - 1))) != 0 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn sigpending(set: *mut Sigset) -> i32 {
    let ret = crate::syscall::sys_rt_sigpending(set as u64, 8);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigsuspend(mask: *const Sigset) -> i32 {
    let ret = crate::syscall::sys_rt_sigsuspend(mask as u64, 8);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
    }
    -1
}
