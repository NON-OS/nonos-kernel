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

use core::sync::atomic::Ordering;

use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

use super::audit::{audit_syscall, SYSCALL_STATS};
use super::crypto::*;
use super::file_io::*;
use super::hardware::*;
use super::network::*;
use super::process::*;
use super::util::errno;

pub fn handle_syscall_dispatch(
    syscall: SyscallNumber,
    a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
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
    a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Read => handle_read(a0 as i32, a1, a2),
        SyscallNumber::Write => handle_write(a0 as i32, a1, a2),
        SyscallNumber::Open => handle_open(a0, a1, a2),
        SyscallNumber::Close => handle_close(a0 as i32),
        SyscallNumber::Stat => handle_stat(a0, a1),
        SyscallNumber::Fstat => handle_fstat(a0 as i32, a1),
        SyscallNumber::Lstat => crate::syscall::extended::handle_lstat(a0, a1),
        SyscallNumber::Poll => crate::syscall::extended::select::handle_poll(a0, a1 as u32, a2 as i32),
        SyscallNumber::Lseek => handle_lseek(a0 as i32, a1 as i64, a2 as i32),
        SyscallNumber::Ioctl => crate::syscall::extended::handle_ioctl(a0 as i32, a1, a2),
        SyscallNumber::Pread64 => crate::syscall::extended::handle_pread64(a0 as i32, a1, a2, a3 as i64),
        SyscallNumber::Pwrite64 => crate::syscall::extended::handle_pwrite64(a0 as i32, a1, a2, a3 as i64),
        SyscallNumber::Readv => crate::syscall::extended::handle_readv(a0 as i32, a1, a2 as i32),
        SyscallNumber::Writev => crate::syscall::extended::handle_writev(a0 as i32, a1, a2 as i32),
        SyscallNumber::Access => crate::syscall::extended::handle_access(a0, a1),
        SyscallNumber::Fcntl => crate::syscall::extended::handle_fcntl(a0 as i32, a1 as i32, a2),
        SyscallNumber::Ftruncate => crate::syscall::extended::handle_ftruncate(a0 as i32, a1),
        SyscallNumber::Truncate => crate::syscall::extended::handle_truncate(a0, a1),
        SyscallNumber::Creat => crate::syscall::extended::handle_creat(a0, a1),
        SyscallNumber::Readlink => crate::syscall::extended::handle_readlink(a0, a1, a2),
        SyscallNumber::Sendfile => crate::syscall::extended::handle_sendfile(a0 as i32, a1 as i32, a2, a3),
        SyscallNumber::Flock => crate::syscall::extended::handle_flock(a0 as i32, a1 as i32),
        SyscallNumber::Fsync => crate::syscall::extended::handle_fsync(a0 as i32),
        SyscallNumber::Fdatasync => crate::syscall::extended::handle_fdatasync(a0 as i32),
        SyscallNumber::Sync => crate::syscall::extended::handle_sync(),
        SyscallNumber::Syncfs => crate::syscall::extended::handle_syncfs(a0 as i32),
        SyscallNumber::Fallocate => crate::syscall::extended::handle_fallocate(a0 as i32, a1 as i32, a2 as i64, a3 as i64),

        SyscallNumber::Dup => crate::syscall::extended::handle_dup(a0),
        SyscallNumber::Dup2 => crate::syscall::extended::handle_dup2(a0, a1),
        SyscallNumber::Dup3 => crate::syscall::extended::handle_dup3(a0, a1, a2),
        SyscallNumber::Pipe => crate::syscall::extended::handle_pipe(a0),
        SyscallNumber::Pipe2 => crate::syscall::extended::handle_pipe2(a0, a1),

        SyscallNumber::Getdents => crate::syscall::extended::handle_getdents(a0 as i32, a1, a2),
        SyscallNumber::Getdents64 => crate::syscall::extended::handle_getdents64(a0, a1, a2),
        SyscallNumber::Getcwd => crate::syscall::extended::handle_getcwd(a0, a1),
        SyscallNumber::Chdir => crate::syscall::extended::handle_chdir(a0),
        SyscallNumber::Fchdir => crate::syscall::extended::handle_fchdir(a0 as i32),
        SyscallNumber::Mkdir => handle_mkdir(a0, a1),
        SyscallNumber::Mkdirat => crate::syscall::extended::handle_mkdirat(a0 as i32, a1, a2),
        SyscallNumber::Rmdir => handle_rmdir(a0),
        SyscallNumber::Unlink => handle_unlink(a0),
        SyscallNumber::Unlinkat => crate::syscall::extended::handle_unlinkat(a0 as i32, a1, a2 as i32),
        SyscallNumber::Rename => handle_rename(a0, a1),
        SyscallNumber::Renameat => crate::syscall::extended::handle_renameat(a0 as i32, a1, a2 as i32, a3),
        SyscallNumber::Renameat2 => crate::syscall::extended::handle_renameat2(a0 as i32, a1, a2 as i32, a3, a4 as u32),
        SyscallNumber::Link => crate::syscall::extended::handle_link(a0, a1),
        SyscallNumber::Linkat => crate::syscall::extended::handle_linkat(a0 as i32, a1, a2 as i32, a3, a4 as i32),
        SyscallNumber::Symlink => crate::syscall::extended::handle_symlink(a0, a1),
        SyscallNumber::Symlinkat => crate::syscall::extended::handle_symlinkat(a0, a1 as i32, a2),
        SyscallNumber::Readlinkat => crate::syscall::extended::handle_readlinkat(a0 as i32, a1, a2, a3),
        SyscallNumber::Chmod => crate::syscall::extended::handle_chmod(a0, a1 as u32),
        SyscallNumber::Fchmod => crate::syscall::extended::handle_fchmod(a0 as i32, a1 as u32),
        SyscallNumber::Fchmodat => crate::syscall::extended::handle_fchmodat(a0 as i32, a1, a2 as u32, a3 as i32),
        SyscallNumber::Chown => crate::syscall::extended::handle_chown(a0, a1 as u32, a2 as u32),
        SyscallNumber::Fchown => crate::syscall::extended::handle_fchown(a0 as i32, a1 as u32, a2 as u32),
        SyscallNumber::Lchown => crate::syscall::extended::handle_lchown(a0, a1 as u32, a2 as u32),
        SyscallNumber::Fchownat => crate::syscall::extended::handle_fchownat(a0 as i32, a1, a2 as u32, a3 as u32, a4 as i32),
        SyscallNumber::Umask => crate::syscall::extended::handle_umask(a0 as u32),
        SyscallNumber::Mknod => crate::syscall::extended::handle_mknod(a0, a1 as u32, a2),
        SyscallNumber::Mknodat => crate::syscall::extended::handle_mknodat(a0 as i32, a1, a2 as u32, a3),
        SyscallNumber::Openat => crate::syscall::extended::handle_openat(a0 as i32, a1, a2 as i32, a3 as u32),
        SyscallNumber::Newfstatat => crate::syscall::extended::handle_newfstatat(a0 as i32, a1, a2, a3 as i32),
        SyscallNumber::Faccessat => crate::syscall::extended::handle_faccessat(a0 as i32, a1, a2 as i32),
        SyscallNumber::Statfs => crate::syscall::extended::handle_statfs(a0, a1),
        SyscallNumber::Fstatfs => crate::syscall::extended::handle_fstatfs(a0 as i32, a1),
        SyscallNumber::Statx => crate::syscall::extended::handle_statx(a0 as i32, a1, a2 as i32, a3 as u32, a4),
        SyscallNumber::Chroot => crate::syscall::extended::handle_chroot(a0),
        SyscallNumber::Mount => crate::syscall::extended::handle_mount(a0, a1, a2, a3, a4),
        SyscallNumber::Umount2 => crate::syscall::extended::handle_umount2(a0, a1 as i32),

        SyscallNumber::Mmap => handle_mmap(a0, a1, a2, a3),
        SyscallNumber::Mprotect => crate::syscall::extended::handle_mprotect(a0, a1, a2),
        SyscallNumber::Munmap => handle_munmap(a0, a1),
        SyscallNumber::Brk => crate::syscall::extended::handle_brk(a0),
        SyscallNumber::Mremap => crate::syscall::extended::handle_mremap(a0, a1, a2, a3),
        SyscallNumber::Msync => crate::syscall::extended::handle_msync(a0, a1, a2 as i32),
        SyscallNumber::Mincore => crate::syscall::extended::handle_mincore(a0, a1, a2),
        SyscallNumber::Madvise => crate::syscall::extended::handle_madvise(a0, a1, a2 as i32),
        SyscallNumber::Mlock => crate::syscall::extended::handle_mlock(a0, a1),
        SyscallNumber::Mlock2 => crate::syscall::extended::handle_mlock2(a0, a1, a2 as i32),
        SyscallNumber::Munlock => crate::syscall::extended::handle_munlock(a0, a1),
        SyscallNumber::Mlockall => crate::syscall::extended::handle_mlockall(a0 as i32),
        SyscallNumber::Munlockall => crate::syscall::extended::handle_munlockall(),
        SyscallNumber::MemfdCreate => crate::syscall::extended::handle_memfd_create(a0, a1 as u32),

        SyscallNumber::RtSigaction => crate::syscall::signals::handle_rt_sigaction(a0, a1, a2, a3),
        SyscallNumber::RtSigprocmask => crate::syscall::signals::handle_rt_sigprocmask(a0, a1, a2, a3),
        SyscallNumber::RtSigreturn => crate::syscall::signals::handle_rt_sigreturn(),
        SyscallNumber::RtSigsuspend => crate::syscall::signals::handle_rt_sigsuspend(a0, a1),
        SyscallNumber::RtSigpending => crate::syscall::signals::handle_rt_sigpending(a0, a1),
        SyscallNumber::RtSigtimedwait => crate::syscall::signals::handle_rt_sigtimedwait(a0, a1, a2, a3),
        SyscallNumber::RtSigqueueinfo => crate::syscall::signals::handle_rt_sigqueueinfo(a0, a1, a2),
        SyscallNumber::RtTgsigqueueinfo => crate::syscall::signals::handle_rt_tgsigqueueinfo(a0, a1, a2, a3),
        SyscallNumber::Sigaltstack => crate::syscall::signals::handle_sigaltstack(a0, a1),
        SyscallNumber::Kill => crate::syscall::signals::handle_kill(a0 as i64, a1),
        SyscallNumber::Tkill => crate::syscall::signals::handle_tkill(a0, a1),
        SyscallNumber::Tgkill => crate::syscall::signals::handle_tgkill(a0, a1, a2),
        SyscallNumber::Pause => crate::syscall::signals::handle_pause(),
        SyscallNumber::Signalfd => crate::syscall::extended::handle_signalfd(a0 as i32, a1, a2),
        SyscallNumber::Signalfd4 => crate::syscall::extended::handle_signalfd4(a0 as i32, a1, a2, a3 as i32),

        SyscallNumber::Exit => handle_exit(a0),
        SyscallNumber::ExitGroup => handle_exit(a0),
        SyscallNumber::Fork => handle_fork(),
        SyscallNumber::Vfork => handle_fork(),
        SyscallNumber::Clone => crate::syscall::extended::handle_clone(a0, a1, a2, a3, a4),
        SyscallNumber::Execve => handle_execve(a0, a1, a2),
        SyscallNumber::Execveat => crate::syscall::extended::handle_execveat(a0 as i32, a1, a2, a3, a4 as i32),
        SyscallNumber::Wait4 => crate::syscall::extended::handle_wait4(a0 as i64, a1, a2, a3),
        SyscallNumber::Waitid => crate::syscall::extended::handle_waitid(a0, a1, a2, a3, a4),
        SyscallNumber::Nanosleep => handle_nanosleep(a0, a1),
        SyscallNumber::ClockNanosleep => crate::syscall::extended::handle_clock_nanosleep(a0, a1, a2, a3),
        SyscallNumber::Yield => handle_yield(),
        SyscallNumber::Futex => crate::syscall::extended::sync::handle_futex(a0, a1 as i32, a2, a3, a4, a5),
        SyscallNumber::Prctl => crate::syscall::extended::handle_prctl(a0 as i32, a1, a2, a3, a4),
        SyscallNumber::ArchPrctl => crate::syscall::extended::handle_arch_prctl(a0 as i32, a1),
        SyscallNumber::SetTidAddress => crate::syscall::extended::handle_set_tid_address(a0),
        SyscallNumber::Seccomp => crate::syscall::extended::handle_seccomp(a0 as u32, a1 as u32, a2),

        SyscallNumber::Getpid => handle_getpid(),
        SyscallNumber::Getppid => crate::syscall::extended::handle_getppid(),
        SyscallNumber::Gettid => crate::syscall::extended::handle_gettid(),
        SyscallNumber::Getpgrp => crate::syscall::extended::handle_getpgrp(),
        SyscallNumber::Getpgid => crate::syscall::extended::handle_getpgid(a0 as i32),
        SyscallNumber::Setpgid => crate::syscall::extended::handle_setpgid(a0 as i32, a1 as i32),
        SyscallNumber::Getsid => crate::syscall::extended::handle_getsid(a0 as i32),
        SyscallNumber::Setsid => crate::syscall::extended::handle_setsid(),
        SyscallNumber::Getuid => crate::syscall::extended::handle_getuid(),
        SyscallNumber::Geteuid => crate::syscall::extended::handle_geteuid(),
        SyscallNumber::Getgid => crate::syscall::extended::handle_getgid(),
        SyscallNumber::Getegid => crate::syscall::extended::handle_getegid(),
        SyscallNumber::Setuid => crate::syscall::extended::handle_setuid(a0 as u32),
        SyscallNumber::Setgid => crate::syscall::extended::handle_setgid(a0 as u32),
        SyscallNumber::Setreuid => crate::syscall::extended::handle_setreuid(a0 as u32, a1 as u32),
        SyscallNumber::Setregid => crate::syscall::extended::handle_setregid(a0 as u32, a1 as u32),
        SyscallNumber::Getresuid => crate::syscall::extended::handle_getresuid(a0, a1, a2),
        SyscallNumber::Setresuid => crate::syscall::extended::handle_setresuid(a0 as u32, a1 as u32, a2 as u32),
        SyscallNumber::Getresgid => crate::syscall::extended::handle_getresgid(a0, a1, a2),
        SyscallNumber::Setresgid => crate::syscall::extended::handle_setresgid(a0 as u32, a1 as u32, a2 as u32),
        SyscallNumber::Setfsuid => crate::syscall::extended::handle_setfsuid(a0 as u32),
        SyscallNumber::Setfsgid => crate::syscall::extended::handle_setfsgid(a0 as u32),
        SyscallNumber::Getgroups => crate::syscall::extended::handle_getgroups(a0 as i32, a1),
        SyscallNumber::Setgroups => crate::syscall::extended::handle_setgroups(a0, a1),
        SyscallNumber::Capget => crate::syscall::extended::handle_capget(a0, a1),
        SyscallNumber::Capset => crate::syscall::extended::handle_capset(a0, a1),

        SyscallNumber::Uname => crate::syscall::extended::handle_uname(a0),
        SyscallNumber::Gettimeofday => crate::syscall::extended::handle_gettimeofday(a0, a1),
        SyscallNumber::Settimeofday => crate::syscall::extended::handle_settimeofday(a0, a1),
        SyscallNumber::ClockGettime => crate::syscall::extended::timer::handle_clock_gettime(a0 as i32, a1),
        SyscallNumber::ClockSettime => crate::syscall::extended::timer::handle_clock_settime(a0 as i32, a1),
        SyscallNumber::ClockGetres => crate::syscall::extended::timer::handle_clock_getres(a0 as i32, a1),
        SyscallNumber::Getrusage => crate::syscall::extended::misc::handle_getrusage(a0, a1),
        SyscallNumber::Times => crate::syscall::extended::handle_times(a0),
        SyscallNumber::Getrlimit => crate::syscall::extended::handle_getrlimit(a0 as u32, a1),
        SyscallNumber::Setrlimit => crate::syscall::extended::handle_setrlimit(a0 as u32, a1),
        SyscallNumber::Prlimit64 => crate::syscall::extended::handle_prlimit64(a0 as i32, a1 as u32, a2, a3),
        SyscallNumber::Sysinfo => crate::syscall::extended::handle_sysinfo(a0),
        SyscallNumber::Syslog => crate::syscall::extended::handle_syslog(a0 as i32, a1, a2 as i32),
        SyscallNumber::Getcpu => crate::syscall::extended::handle_getcpu(a0, a1, a2),
        SyscallNumber::Sethostname => crate::syscall::extended::handle_sethostname(a0, a1),
        SyscallNumber::Setdomainname => crate::syscall::extended::handle_setdomainname(a0, a1),

        SyscallNumber::Alarm => crate::syscall::extended::handle_alarm(a0 as u32),
        SyscallNumber::Getitimer => crate::syscall::extended::handle_getitimer(a0 as i32, a1),
        SyscallNumber::Setitimer => crate::syscall::extended::handle_setitimer(a0 as i32, a1, a2),
        SyscallNumber::TimerCreate => crate::syscall::extended::handle_timer_create(a0, a1, a2),
        SyscallNumber::TimerSettime => crate::syscall::extended::handle_timer_settime(a0 as i32, a1 as i32, a2, a3),
        SyscallNumber::TimerGettime => crate::syscall::extended::handle_timer_gettime(a0 as i32, a1),
        SyscallNumber::TimerGetoverrun => crate::syscall::extended::handle_timer_getoverrun(a0 as i32),
        SyscallNumber::TimerDelete => crate::syscall::extended::handle_timer_delete(a0 as i32),
        SyscallNumber::TimerfdCreate => crate::syscall::extended::handle_timerfd_create(a0 as i32, a1 as i32),
        SyscallNumber::TimerfdSettime => crate::syscall::extended::handle_timerfd_settime(a0 as i32, a1 as i32, a2, a3),
        SyscallNumber::TimerfdGettime => crate::syscall::extended::handle_timerfd_gettime(a0 as i32, a1),
        SyscallNumber::Utime => crate::syscall::extended::handle_utime(a0, a1),
        SyscallNumber::Utimes => crate::syscall::extended::handle_utimes(a0, a1),
        SyscallNumber::Utimensat => crate::syscall::extended::handle_utimensat(a0 as i32, a1, a2, a3 as i32),
        SyscallNumber::Futimesat => crate::syscall::extended::handle_futimesat(a0 as i32, a1, a2),

        SyscallNumber::EpollCreate => crate::syscall::extended::handle_epoll_create(a0 as i32),
        SyscallNumber::EpollCreate1 => crate::syscall::extended::handle_epoll_create1(a0 as i32),
        SyscallNumber::EpollCtl => crate::syscall::extended::handle_epoll_ctl(a0 as i32, a1 as i32, a2 as i32, a3),
        SyscallNumber::EpollWait => crate::syscall::extended::handle_epoll_wait(a0 as i32, a1, a2 as i32, a3 as i32),
        SyscallNumber::EpollPwait => crate::syscall::extended::handle_epoll_pwait(a0 as i32, a1, a2 as i32, a3 as i32, a4, a5),

        SyscallNumber::Eventfd => crate::syscall::extended::handle_eventfd(a0 as u32),
        SyscallNumber::Eventfd2 => crate::syscall::extended::handle_eventfd2(a0 as u32, a1 as i32),

        SyscallNumber::InotifyInit => crate::syscall::extended::handle_inotify_init(),
        SyscallNumber::InotifyInit1 => crate::syscall::extended::handle_inotify_init1(a0 as i32),
        SyscallNumber::InotifyAddWatch => crate::syscall::extended::handle_inotify_add_watch(a0 as i32, a1, a2 as u32),
        SyscallNumber::InotifyRmWatch => crate::syscall::extended::handle_inotify_rm_watch(a0 as i32, a1 as i32),

        SyscallNumber::Select => crate::syscall::extended::handle_select(a0 as i32, a1, a2, a3, a4),
        SyscallNumber::Pselect6 => crate::syscall::extended::handle_pselect6(a0 as i32, a1, a2, a3, a4, a5),
        SyscallNumber::Ppoll => crate::syscall::extended::handle_ppoll(a0, a1 as u32, a2, a3, a4),

        SyscallNumber::Socket => handle_socket(a0, a1, a2),
        SyscallNumber::Connect => handle_connect(a0, a1, a2, a3),
        SyscallNumber::Accept => handle_accept(a0, a1, a2),
        SyscallNumber::Accept4 => handle_accept4(a0, a1, a2, a3 as i32),
        SyscallNumber::Sendto => handle_sendto(a0, a1, a2, a3),
        SyscallNumber::Recvfrom => handle_recvfrom(a0, a1, a2, a3),
        SyscallNumber::Sendmsg => handle_sendmsg(a0, a1, a2),
        SyscallNumber::Recvmsg => handle_recvmsg(a0, a1, a2),
        SyscallNumber::Sendmmsg => handle_sendmmsg(a0, a1, a2, a3),
        SyscallNumber::Recvmmsg => handle_recvmmsg(a0, a1, a2, a3, a4),
        SyscallNumber::Shutdown => handle_shutdown(a0 as i32, a1 as i32),
        SyscallNumber::Bind => handle_bind(a0, a1, a2),
        SyscallNumber::Listen => handle_listen(a0, a1),
        SyscallNumber::Getsockname => handle_getsockname(a0, a1, a2),
        SyscallNumber::Getpeername => handle_getpeername(a0, a1, a2),
        SyscallNumber::Socketpair => handle_socketpair(a0, a1, a2, a3),
        SyscallNumber::Setsockopt => handle_setsockopt(a0, a1, a2, a3, a4),
        SyscallNumber::Getsockopt => handle_getsockopt(a0, a1, a2, a3, a4),

        SyscallNumber::Shmget => crate::syscall::extended::handle_shmget(a0, a1, a2 as i32),
        SyscallNumber::Shmat => crate::syscall::extended::handle_shmat(a0 as i32, a1, a2 as i32),
        SyscallNumber::Shmdt => crate::syscall::extended::handle_shmdt(a0),
        SyscallNumber::Shmctl => crate::syscall::extended::handle_shmctl(a0 as i32, a1 as i32, a2),
        SyscallNumber::Semget => crate::syscall::extended::handle_semget(a0, a1 as i32, a2 as i32),
        SyscallNumber::Semop => crate::syscall::extended::handle_semop(a0 as i32, a1, a2),
        SyscallNumber::Semctl => crate::syscall::extended::handle_semctl(a0 as i32, a1 as i32, a2 as i32, a3),
        SyscallNumber::Semtimedop => crate::syscall::extended::handle_semtimedop(a0 as i32, a1, a2, a3),
        SyscallNumber::Msgget => crate::syscall::extended::handle_msgget(a0, a1 as i32),
        SyscallNumber::Msgsnd => crate::syscall::extended::handle_msgsnd(a0 as i32, a1, a2, a3 as i32),
        SyscallNumber::Msgrcv => crate::syscall::extended::handle_msgrcv(a0 as i32, a1, a2, a3 as i64, a4 as i32),
        SyscallNumber::Msgctl => crate::syscall::extended::handle_msgctl(a0 as i32, a1 as i32, a2),

        SyscallNumber::IpcSend => handle_ipc_send(a0, a1, a2),
        SyscallNumber::IpcRecv => handle_ipc_recv(a0, a1, a2),
        SyscallNumber::IpcCreate => handle_ipc_create(a0),
        SyscallNumber::IpcDestroy => handle_ipc_destroy(a0),

        SyscallNumber::CryptoRandom => handle_crypto_random(a0, a1),
        SyscallNumber::Getrandom => crate::syscall::extended::handle_getrandom(a0, a1, a2 as u32),
        SyscallNumber::CryptoHash => handle_crypto_hash(a0, a1, a2),
        SyscallNumber::CryptoSign => handle_crypto_sign(a0, a1, a2, a3),
        SyscallNumber::CryptoVerify => handle_crypto_verify(a0, a1, a2, a3),
        SyscallNumber::CryptoEncrypt => handle_crypto_encrypt(a0, a1, a2, a3, a4, a5),
        SyscallNumber::CryptoDecrypt => handle_crypto_decrypt(a0, a1, a2, a3, a4, a5),
        SyscallNumber::CryptoKeyGen => handle_crypto_keygen(a0, a1, a2),
        SyscallNumber::CryptoZkProve => handle_crypto_zk_prove(a0, a1, a2, a3),
        SyscallNumber::CryptoZkVerify => handle_crypto_zk_verify(a0, a1, a2, a3),

        SyscallNumber::IoPortRead => handle_io_port_read(a0 as u16),
        SyscallNumber::IoPortWrite => handle_io_port_write(a0 as u16, a1 as u8),
        SyscallNumber::MmioMap => handle_mmio_map(a0, a1, a2),
        SyscallNumber::Iopl => crate::syscall::extended::handle_iopl(a0 as i32),
        SyscallNumber::Ioperm => crate::syscall::extended::handle_ioperm(a0, a1, a2 as i32),

        SyscallNumber::DebugLog => handle_debug_log(a0, a1),
        SyscallNumber::DebugTrace => handle_debug_trace(a0),
        SyscallNumber::Ptrace => crate::syscall::extended::handle_ptrace(a0 as i64, a1 as i64, a2, a3),

        SyscallNumber::AdminReboot => handle_admin_reboot(),
        SyscallNumber::AdminShutdown => handle_admin_shutdown(),
        SyscallNumber::AdminModLoad => handle_admin_mod_load(a0, a1, a2, a3, a4),
        SyscallNumber::AdminCapGrant => handle_admin_cap_grant(a0 as u32, a1, a2),
        SyscallNumber::AdminCapRevoke => handle_admin_cap_revoke(a0 as u32, a1),
        SyscallNumber::Reboot => crate::syscall::extended::handle_reboot(a0 as i32, a1 as i32, a2 as u32, a3),
        SyscallNumber::InitModule => crate::syscall::extended::handle_init_module(a0, a1, a2),
        SyscallNumber::DeleteModule => crate::syscall::extended::handle_delete_module(a0, a1 as u32),
        SyscallNumber::FinitModule => crate::syscall::extended::handle_finit_module(a0 as i32, a1, a2 as i32),
        SyscallNumber::Acct => crate::syscall::extended::handle_acct(a0),
        SyscallNumber::Swapon => crate::syscall::extended::handle_swapon(a0, a1 as i32),
        SyscallNumber::Swapoff => crate::syscall::extended::handle_swapoff(a0),
        SyscallNumber::Quotactl => crate::syscall::extended::handle_quotactl(a0 as u32, a1, a2 as i32, a3),

        SyscallNumber::SchedSetparam => crate::syscall::extended::handle_sched_setparam(a0 as i32, a1),
        SyscallNumber::SchedGetparam => crate::syscall::extended::handle_sched_getparam(a0 as i32, a1),
        SyscallNumber::SchedSetscheduler => crate::syscall::extended::handle_sched_setscheduler(a0 as i32, a1 as i32, a2),
        SyscallNumber::SchedGetscheduler => crate::syscall::extended::handle_sched_getscheduler(a0 as i32),
        SyscallNumber::SchedGetPriorityMax => crate::syscall::extended::handle_sched_get_priority_max(a0 as i32),
        SyscallNumber::SchedGetPriorityMin => crate::syscall::extended::handle_sched_get_priority_min(a0 as i32),
        SyscallNumber::SchedRrGetInterval => crate::syscall::extended::handle_sched_rr_get_interval(a0 as i32, a1),
        SyscallNumber::SchedSetaffinity => crate::syscall::extended::handle_sched_setaffinity(a0 as i32, a1, a2),
        SyscallNumber::SchedGetaffinity => crate::syscall::extended::handle_sched_getaffinity(a0 as i32, a1, a2),
        SyscallNumber::SchedSetattr => crate::syscall::extended::handle_sched_setattr(a0 as i32, a1, a2 as u32),
        SyscallNumber::SchedGetattr => crate::syscall::extended::handle_sched_getattr(a0 as i32, a1, a2 as u32, a3 as u32),
        SyscallNumber::Getpriority => crate::syscall::extended::handle_getpriority(a0 as i32, a1 as u32),
        SyscallNumber::Setpriority => crate::syscall::extended::handle_setpriority(a0 as i32, a1 as u32, a2 as i32),
        SyscallNumber::IoprioSet => crate::syscall::extended::handle_ioprio_set(a0 as i32, a1 as i32, a2 as i32),
        SyscallNumber::IoprioGet => crate::syscall::extended::handle_ioprio_get(a0 as i32, a1 as i32),

        _ => errno(38),
    }
}
