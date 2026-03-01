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

use super::caps::current_caps;
use super::dispatch::handle_syscall_dispatch;
use super::numbers::SyscallNumber;

#[inline(always)]
fn ret_errno(e: i32) -> u64 {
    (-(e as i64)) as u64
}

#[inline(always)]
pub fn handle_syscall(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let Some(sc) = SyscallNumber::from_u64(id) else {
        return ret_errno(38);
    };

    let caps = match current_caps() {
        Some(c) => c,
        None => return ret_errno(1),
    };
    let allowed = check_capability(&caps, sc);

    if !allowed {
        return ret_errno(1);
    }

    let r = handle_syscall_dispatch(sc, a0, a1, a2, a3, a4, a5);
    r.value as u64
}

fn check_capability(caps: &crate::capabilities::CapabilityToken, sc: SyscallNumber) -> bool {
    match sc {
        SyscallNumber::Read | SyscallNumber::Pread64 | SyscallNumber::Readv | SyscallNumber::Preadv => caps.can_read(),
        SyscallNumber::Write | SyscallNumber::Pwrite64 | SyscallNumber::Writev | SyscallNumber::Pwritev => caps.can_write(),
        SyscallNumber::Open | SyscallNumber::Openat | SyscallNumber::Creat => caps.can_open_files(),
        SyscallNumber::Close => caps.can_close_files(),
        SyscallNumber::Stat | SyscallNumber::Fstat | SyscallNumber::Lstat | SyscallNumber::Newfstatat | SyscallNumber::Statx => caps.can_stat(),
        SyscallNumber::Poll | SyscallNumber::Ppoll | SyscallNumber::Select | SyscallNumber::Pselect6 => caps.can_read(),
        SyscallNumber::Lseek => caps.can_seek(),
        SyscallNumber::Ioctl => caps.can_read(),
        SyscallNumber::Access | SyscallNumber::Faccessat => caps.can_stat(),
        SyscallNumber::Fcntl => caps.can_read(),
        SyscallNumber::Ftruncate | SyscallNumber::Truncate | SyscallNumber::Fallocate => caps.can_write(),
        SyscallNumber::Readlink | SyscallNumber::Readlinkat => caps.can_read(),
        SyscallNumber::Sendfile | SyscallNumber::CopyFileRange => caps.can_read(),
        SyscallNumber::Flock | SyscallNumber::Fsync | SyscallNumber::Fdatasync | SyscallNumber::Sync | SyscallNumber::Syncfs => caps.can_write(),

        SyscallNumber::Dup | SyscallNumber::Dup2 | SyscallNumber::Dup3 => true,
        SyscallNumber::Pipe | SyscallNumber::Pipe2 => caps.can_open_files(),

        SyscallNumber::Getdents | SyscallNumber::Getdents64 => caps.can_read(),
        SyscallNumber::Getcwd => true,
        SyscallNumber::Chdir | SyscallNumber::Fchdir => caps.can_stat(),
        SyscallNumber::Mkdir | SyscallNumber::Mkdirat => caps.can_modify_dirs(),
        SyscallNumber::Rmdir => caps.can_modify_dirs(),
        SyscallNumber::Unlink | SyscallNumber::Unlinkat => caps.can_unlink(),
        SyscallNumber::Rename | SyscallNumber::Renameat | SyscallNumber::Renameat2 => caps.can_modify_dirs(),
        SyscallNumber::Link | SyscallNumber::Linkat => caps.can_modify_dirs(),
        SyscallNumber::Symlink | SyscallNumber::Symlinkat => caps.can_modify_dirs(),
        SyscallNumber::Chmod | SyscallNumber::Fchmod | SyscallNumber::Fchmodat => caps.can_modify_dirs(),
        SyscallNumber::Chown | SyscallNumber::Fchown | SyscallNumber::Lchown | SyscallNumber::Fchownat => caps.can_modify_dirs(),
        SyscallNumber::Mknod | SyscallNumber::Mknodat => caps.can_modify_dirs(),
        SyscallNumber::Chroot => caps.can_admin(),
        SyscallNumber::Mount | SyscallNumber::Umount2 => caps.can_admin(),
        SyscallNumber::Statfs | SyscallNumber::Fstatfs => caps.can_stat(),

        SyscallNumber::Mmap | SyscallNumber::Mprotect | SyscallNumber::Mremap => caps.can_allocate_memory(),
        SyscallNumber::Munmap => caps.can_deallocate_memory(),
        SyscallNumber::Brk => caps.can_allocate_memory(),
        SyscallNumber::Msync | SyscallNumber::Mincore | SyscallNumber::Madvise => caps.can_allocate_memory(),
        SyscallNumber::Mlock | SyscallNumber::Mlock2 | SyscallNumber::Munlock | SyscallNumber::Mlockall | SyscallNumber::Munlockall => caps.can_allocate_memory(),
        SyscallNumber::MemfdCreate => caps.can_allocate_memory(),

        SyscallNumber::RtSigaction | SyscallNumber::RtSigprocmask | SyscallNumber::RtSigreturn => true,
        SyscallNumber::RtSigsuspend | SyscallNumber::RtSigpending | SyscallNumber::RtSigtimedwait => true,
        SyscallNumber::Sigaltstack | SyscallNumber::Pause => true,
        SyscallNumber::RtSigqueueinfo | SyscallNumber::RtTgsigqueueinfo => caps.can_signal(),
        SyscallNumber::Kill | SyscallNumber::Tkill | SyscallNumber::Tgkill => caps.can_signal(),
        SyscallNumber::Signalfd | SyscallNumber::Signalfd4 => true,

        SyscallNumber::Exit | SyscallNumber::ExitGroup => caps.can_exit(),
        SyscallNumber::Fork | SyscallNumber::Vfork | SyscallNumber::Clone => caps.can_fork(),
        SyscallNumber::Execve | SyscallNumber::Execveat => caps.can_exec(),
        SyscallNumber::Wait4 | SyscallNumber::Waitid => caps.can_wait(),
        SyscallNumber::Nanosleep | SyscallNumber::ClockNanosleep => true,
        SyscallNumber::Yield => true,
        SyscallNumber::Futex => true,
        SyscallNumber::Prctl | SyscallNumber::ArchPrctl => true,
        SyscallNumber::SetTidAddress => true,
        SyscallNumber::Seccomp => caps.can_admin(),

        SyscallNumber::Getpid => caps.can_getpid(),
        SyscallNumber::Getppid | SyscallNumber::Gettid | SyscallNumber::Getpgrp | SyscallNumber::Getpgid | SyscallNumber::Getsid => true,
        SyscallNumber::Getuid | SyscallNumber::Geteuid | SyscallNumber::Getgid | SyscallNumber::Getegid => true,
        SyscallNumber::Getresuid | SyscallNumber::Getresgid | SyscallNumber::Getgroups => true,
        SyscallNumber::Setuid | SyscallNumber::Setgid | SyscallNumber::Setreuid | SyscallNumber::Setregid => caps.can_admin(),
        SyscallNumber::Setresuid | SyscallNumber::Setresgid | SyscallNumber::Setgroups => caps.can_admin(),
        SyscallNumber::Setfsuid | SyscallNumber::Setfsgid => caps.can_admin(),
        SyscallNumber::Setpgid | SyscallNumber::Setsid => true,
        SyscallNumber::Capget | SyscallNumber::Capset => true,
        SyscallNumber::Umask => true,

        SyscallNumber::Uname => true,
        SyscallNumber::Gettimeofday | SyscallNumber::Settimeofday => true,
        SyscallNumber::ClockGettime | SyscallNumber::ClockSettime | SyscallNumber::ClockGetres => true,
        SyscallNumber::Getrusage | SyscallNumber::Times => true,
        SyscallNumber::Getrlimit | SyscallNumber::Setrlimit | SyscallNumber::Prlimit64 => true,
        SyscallNumber::Sysinfo => true,
        SyscallNumber::Syslog => caps.can_admin(),
        SyscallNumber::Getcpu => true,
        SyscallNumber::Sethostname | SyscallNumber::Setdomainname => caps.can_admin(),

        SyscallNumber::Alarm | SyscallNumber::Getitimer | SyscallNumber::Setitimer => true,
        SyscallNumber::TimerCreate | SyscallNumber::TimerSettime | SyscallNumber::TimerGettime | SyscallNumber::TimerGetoverrun | SyscallNumber::TimerDelete => true,
        SyscallNumber::TimerfdCreate | SyscallNumber::TimerfdSettime | SyscallNumber::TimerfdGettime => true,
        SyscallNumber::Utime | SyscallNumber::Utimes | SyscallNumber::Utimensat | SyscallNumber::Futimesat => caps.can_write(),

        SyscallNumber::EpollCreate | SyscallNumber::EpollCreate1 => true,
        SyscallNumber::EpollCtl | SyscallNumber::EpollCtlOld => true,
        SyscallNumber::EpollWait | SyscallNumber::EpollWaitOld | SyscallNumber::EpollPwait => true,

        SyscallNumber::Eventfd | SyscallNumber::Eventfd2 => true,

        SyscallNumber::InotifyInit | SyscallNumber::InotifyInit1 => true,
        SyscallNumber::InotifyAddWatch | SyscallNumber::InotifyRmWatch => true,

        SyscallNumber::Socket | SyscallNumber::Socketpair => caps.can_network(),
        SyscallNumber::Connect | SyscallNumber::Accept | SyscallNumber::Accept4 => caps.can_network(),
        SyscallNumber::Bind | SyscallNumber::Listen => caps.can_network(),
        SyscallNumber::Sendto | SyscallNumber::Recvfrom => caps.can_network(),
        SyscallNumber::Sendmsg | SyscallNumber::Recvmsg | SyscallNumber::Sendmmsg | SyscallNumber::Recvmmsg => caps.can_network(),
        SyscallNumber::Shutdown => caps.can_network(),
        SyscallNumber::Getsockname | SyscallNumber::Getpeername => caps.can_network(),
        SyscallNumber::Setsockopt | SyscallNumber::Getsockopt => caps.can_network(),

        SyscallNumber::Shmget | SyscallNumber::Shmat | SyscallNumber::Shmdt | SyscallNumber::Shmctl => caps.can_ipc(),
        SyscallNumber::Semget | SyscallNumber::Semop | SyscallNumber::Semctl | SyscallNumber::Semtimedop => caps.can_ipc(),
        SyscallNumber::Msgget | SyscallNumber::Msgsnd | SyscallNumber::Msgrcv | SyscallNumber::Msgctl => caps.can_ipc(),

        SyscallNumber::IpcSend | SyscallNumber::IpcRecv | SyscallNumber::IpcCreate | SyscallNumber::IpcDestroy => caps.can_ipc(),

        SyscallNumber::CryptoRandom | SyscallNumber::Getrandom => caps.can_crypto(),
        SyscallNumber::CryptoHash | SyscallNumber::CryptoSign | SyscallNumber::CryptoVerify => caps.can_crypto(),
        SyscallNumber::CryptoEncrypt | SyscallNumber::CryptoDecrypt => caps.can_crypto(),
        SyscallNumber::CryptoKeyGen | SyscallNumber::CryptoZkProve | SyscallNumber::CryptoZkVerify => caps.can_crypto(),

        SyscallNumber::IoPortRead | SyscallNumber::IoPortWrite | SyscallNumber::MmioMap => caps.can_hardware(),
        SyscallNumber::Iopl | SyscallNumber::Ioperm => caps.can_hardware(),

        SyscallNumber::DebugLog | SyscallNumber::DebugTrace => caps.can_debug(),
        SyscallNumber::Ptrace => caps.can_debug(),

        SyscallNumber::AdminReboot | SyscallNumber::AdminShutdown => caps.can_admin(),
        SyscallNumber::AdminModLoad | SyscallNumber::AdminCapGrant | SyscallNumber::AdminCapRevoke => caps.can_admin(),
        SyscallNumber::Reboot => caps.can_admin(),
        SyscallNumber::InitModule | SyscallNumber::DeleteModule | SyscallNumber::FinitModule => caps.can_admin(),
        SyscallNumber::KexecLoad | SyscallNumber::KexecFileLoad => caps.can_admin(),
        SyscallNumber::Acct => caps.can_admin(),
        SyscallNumber::Swapon | SyscallNumber::Swapoff => caps.can_admin(),
        SyscallNumber::Quotactl => caps.can_admin(),

        SyscallNumber::SchedSetparam | SyscallNumber::SchedGetparam => true,
        SyscallNumber::SchedSetscheduler | SyscallNumber::SchedGetscheduler => true,
        SyscallNumber::SchedGetPriorityMax | SyscallNumber::SchedGetPriorityMin | SyscallNumber::SchedRrGetInterval => true,
        SyscallNumber::SchedSetaffinity | SyscallNumber::SchedGetaffinity => true,
        SyscallNumber::SchedSetattr | SyscallNumber::SchedGetattr => true,
        SyscallNumber::Getpriority | SyscallNumber::Setpriority => true,
        SyscallNumber::IoprioSet | SyscallNumber::IoprioGet => true,

        _ => true,
    }
}

#[no_mangle]
pub extern "C" fn handle_interrupt() {
    // SAFETY: This function is called from assembly syscall entry point.
    // Registers contain the syscall arguments per Linux x86_64 ABI.
    unsafe {
        let (rax, rdi, rsi, rdx, r10, r8, r9): (u64, u64, u64, u64, u64, u64, u64);
        ::core::arch::asm!(
            "mov {rax}, rax",
            "mov {rdi}, rdi",
            "mov {rsi}, rsi",
            "mov {rdx}, rdx",
            "mov {r10}, r10",
            "mov {r8},  r8",
            "mov {r9},  r9",
            rax = out(reg) rax,
            rdi = out(reg) rdi,
            rsi = out(reg) rsi,
            rdx = out(reg) rdx,
            r10 = out(reg) r10,
            r8  = out(reg) r8,
            r9  = out(reg) r9,
            options(nostack, preserves_flags),
        );
        let res = handle_syscall(rax, rdi, rsi, rdx, r10, r8, r9);
        ::core::arch::asm!("mov rax, {res}", res = in(reg) res, options(nostack, preserves_flags));
    }
}
