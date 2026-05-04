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

mod crypto;
mod file_fs;
mod memory;
mod process;
mod signal;
mod time;

// Network sockets and hardware/admin (raw I/O port + MMIO + admin
// reboot/shutdown/modload) are not on the microkernel trusted path.
// The corresponding SyscallNumber arms below are gated; with the
// legacy tree off, they fall through to `file_fs::dispatch_file_fs`,
// whose default arm returns errno(38) (ENOSYS). Honest failure mode,
// no fake success.
#[cfg(feature = "nonos-legacy-tree")]
mod admin;
#[cfg(feature = "nonos-legacy-tree")]
mod network;

use super::audit::{audit_syscall, SYSCALL_STATS};
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;
use core::sync::atomic::Ordering;

pub(crate) fn handle_syscall_dispatch(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    SYSCALL_STATS.total_calls.fetch_add(1, Ordering::Relaxed);
    let result = dispatch_syscall(syscall, a0, a1, a2, a3, a4, a5);
    if result.value >= 0 {
        SYSCALL_STATS.successful_calls.fetch_add(1, Ordering::Relaxed);
    } else {
        SYSCALL_STATS.failed_calls.fetch_add(1, Ordering::Relaxed);
        if result.value == -1 {
            SYSCALL_STATS.permission_denied.fetch_add(1, Ordering::Relaxed);
        }
    }
    if result.audit_required {
        audit_syscall(syscall, [a0, a1, a2, a3], &result);
    }
    result
}

fn dispatch_syscall(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Exit
        | SyscallNumber::ExitGroup
        | SyscallNumber::Fork
        | SyscallNumber::Vfork
        | SyscallNumber::Clone
        | SyscallNumber::Execve
        | SyscallNumber::Execveat
        | SyscallNumber::Wait4
        | SyscallNumber::Waitid
        | SyscallNumber::Nanosleep
        | SyscallNumber::ClockNanosleep
        | SyscallNumber::Yield
        | SyscallNumber::Futex
        | SyscallNumber::Prctl
        | SyscallNumber::ArchPrctl
        | SyscallNumber::SetTidAddress
        | SyscallNumber::Seccomp
        | SyscallNumber::Getpid
        | SyscallNumber::Getppid
        | SyscallNumber::Gettid
        | SyscallNumber::Getpgrp
        | SyscallNumber::Getpgid
        | SyscallNumber::Setpgid
        | SyscallNumber::Getsid
        | SyscallNumber::Setsid
        | SyscallNumber::Getuid
        | SyscallNumber::Geteuid
        | SyscallNumber::Getgid
        | SyscallNumber::Getegid
        | SyscallNumber::Setuid
        | SyscallNumber::Setgid
        | SyscallNumber::Setreuid
        | SyscallNumber::Setregid
        | SyscallNumber::Getresuid
        | SyscallNumber::Setresuid
        | SyscallNumber::Getresgid
        | SyscallNumber::Setresgid
        | SyscallNumber::Setfsuid
        | SyscallNumber::Setfsgid
        | SyscallNumber::Getgroups
        | SyscallNumber::Setgroups
        | SyscallNumber::Capget
        | SyscallNumber::Capset
        | SyscallNumber::CapDrop => process::dispatch_process(syscall, a0, a1, a2, a3, a4, a5),

        SyscallNumber::RtSigaction
        | SyscallNumber::RtSigprocmask
        | SyscallNumber::RtSigreturn
        | SyscallNumber::RtSigsuspend
        | SyscallNumber::RtSigpending
        | SyscallNumber::RtSigtimedwait
        | SyscallNumber::RtSigqueueinfo
        | SyscallNumber::RtTgsigqueueinfo
        | SyscallNumber::Sigaltstack
        | SyscallNumber::Kill
        | SyscallNumber::Tkill
        | SyscallNumber::Tgkill
        | SyscallNumber::Pause
        | SyscallNumber::Signalfd
        | SyscallNumber::Signalfd4 => signal::dispatch_signal(syscall, a0, a1, a2, a3, a4, a5),

        SyscallNumber::Uname
        | SyscallNumber::Gettimeofday
        | SyscallNumber::Settimeofday
        | SyscallNumber::ClockGettime
        | SyscallNumber::ClockSettime
        | SyscallNumber::ClockGetres
        | SyscallNumber::Getrusage
        | SyscallNumber::Times
        | SyscallNumber::Getrlimit
        | SyscallNumber::Setrlimit
        | SyscallNumber::Prlimit64
        | SyscallNumber::Sysinfo
        | SyscallNumber::Alarm
        | SyscallNumber::Getitimer
        | SyscallNumber::Setitimer
        | SyscallNumber::TimerCreate
        | SyscallNumber::TimerSettime
        | SyscallNumber::TimerGettime
        | SyscallNumber::TimerGetoverrun
        | SyscallNumber::TimerDelete
        | SyscallNumber::TimerfdCreate
        | SyscallNumber::TimerfdSettime
        | SyscallNumber::TimerfdGettime
        | SyscallNumber::Utime
        | SyscallNumber::Utimes
        | SyscallNumber::Utimensat
        | SyscallNumber::Futimesat => time::dispatch_time(syscall, a0, a1, a2, a3, a4, a5),

        SyscallNumber::Mmap
        | SyscallNumber::Mprotect
        | SyscallNumber::Munmap
        | SyscallNumber::Brk
        | SyscallNumber::Mremap
        | SyscallNumber::Msync
        | SyscallNumber::Mincore
        | SyscallNumber::Madvise
        | SyscallNumber::Mlock
        | SyscallNumber::Munlock
        | SyscallNumber::Mlockall
        | SyscallNumber::Munlockall
        | SyscallNumber::Mlock2
        | SyscallNumber::Mbind
        | SyscallNumber::SetMempolicy
        | SyscallNumber::GetMempolicy
        | SyscallNumber::MigratePages
        | SyscallNumber::MovePages => memory::dispatch_memory(syscall, a0, a1, a2, a3, a4, a5),

        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::Socket
        | SyscallNumber::Connect
        | SyscallNumber::Accept
        | SyscallNumber::Accept4
        | SyscallNumber::Sendto
        | SyscallNumber::Recvfrom
        | SyscallNumber::Sendmsg
        | SyscallNumber::Recvmsg
        | SyscallNumber::Recvmmsg
        | SyscallNumber::Sendmmsg
        | SyscallNumber::Shutdown
        | SyscallNumber::Bind
        | SyscallNumber::Listen
        | SyscallNumber::Getsockname
        | SyscallNumber::Getpeername
        | SyscallNumber::Socketpair
        | SyscallNumber::Setsockopt
        | SyscallNumber::Getsockopt => network::dispatch_network(syscall, a0, a1, a2, a3, a4, a5),

        SyscallNumber::CryptoRandom
        | SyscallNumber::CryptoHash
        | SyscallNumber::CryptoSign
        | SyscallNumber::CryptoVerify
        | SyscallNumber::CryptoEncrypt
        | SyscallNumber::CryptoDecrypt
        | SyscallNumber::CryptoKeyGen
        | SyscallNumber::CryptoZkProve
        | SyscallNumber::CryptoZkVerify => crypto::dispatch_crypto(syscall, a0, a1, a2, a3, a4, a5),

        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::IoPortRead
        | SyscallNumber::IoPortWrite
        | SyscallNumber::MmioMap
        | SyscallNumber::DebugLog
        | SyscallNumber::DebugTrace
        | SyscallNumber::AdminReboot
        | SyscallNumber::AdminShutdown
        | SyscallNumber::AdminModLoad
        | SyscallNumber::AdminCapGrant
        | SyscallNumber::AdminCapRevoke => admin::dispatch_admin(syscall, a0, a1, a2, a3, a4, a5),

        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsDisplayDimensions => {
            crate::syscall::graphics_surface::sys_display_dimensions(a0 as u32)
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsSurfaceCreate => {
            crate::syscall::graphics_surface::sys_surface_create(a0 as u32, a1 as u32, a2 as u32)
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsSurfaceDestroy => {
            crate::syscall::graphics_surface::sys_surface_destroy(a0)
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsSurfaceMap => {
            crate::syscall::graphics_surface::sys_surface_map(a0)
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsSurfacePresentFull => {
            crate::syscall::graphics_surface::sys_surface_present_full(a0 as u32, a1)
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsSurfacePresentRect => {
            crate::syscall::graphics_surface::sys_surface_present_rect(
                a0 as u32, a1, a2 as u32, a3 as u32, a4 as u32, a5 as u32,
            )
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsDisplayList => {
            crate::syscall::graphics_surface::sys_display_list(a0, a1 as u32)
        }
        #[cfg(feature = "nonos-legacy-tree")]
        SyscallNumber::GraphicsCursorPresent => {
            crate::syscall::graphics_surface::sys_cursor_present(
                a0 as u32, a1, a2 as u32, a3 as u32,
            )
        }

        SyscallNumber::MkIpcSend
        | SyscallNumber::MkIpcRecv
        | SyscallNumber::MkIpcCall
        | SyscallNumber::MkMmap
        | SyscallNumber::MkMunmap
        | SyscallNumber::MkSpawn
        | SyscallNumber::MkExit
        | SyscallNumber::MkYield
        | SyscallNumber::MkCapGrant
        | SyscallNumber::MkCapRevoke
        | SyscallNumber::MkCapCheck => {
            let result = crate::syscall::microkernel::dispatch_microkernel_syscall(
                syscall as u64,
                a0,
                a1,
                a2,
                a3,
                a4,
            );
            SyscallResult { value: result, capability_consumed: false, audit_required: true }
        }

        _ => file_fs::dispatch_file_fs(syscall, a0, a1, a2, a3, a4, a5),
    }
}
