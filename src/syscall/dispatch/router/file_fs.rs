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

use crate::syscall::dispatch::file_io::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_file_fs(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Read => handle_read(a0 as i32, a1, a2),
        SyscallNumber::Write => handle_write(a0 as i32, a1, a2),
        SyscallNumber::Open => handle_open(a0, a1, a2),
        SyscallNumber::Close => handle_close(a0 as i32),
        SyscallNumber::Stat => handle_stat(a0, a1),
        SyscallNumber::Fstat => handle_fstat(a0 as i32, a1),
        SyscallNumber::Lstat => crate::syscall::extended::handle_lstat(a0, a1),
        SyscallNumber::Poll => {
            crate::syscall::extended::select::handle_poll(a0, a1 as u32, a2 as i32)
        }
        SyscallNumber::Select => {
            crate::syscall::extended::select::handle_select(a0 as i32, a1, a2, a3, a4)
        }
        SyscallNumber::Pselect6 => {
            crate::syscall::extended::select::handle_pselect6(a0 as i32, a1, a2, a3, a4, _a5)
        }
        SyscallNumber::Ppoll => {
            crate::syscall::extended::select::handle_ppoll(a0, a1 as u32, a2, a3, a4)
        }
        SyscallNumber::EpollCreate => {
            crate::syscall::extended::epoll::handle_epoll_create(a0 as i32)
        }
        SyscallNumber::EpollCreate1 => {
            crate::syscall::extended::epoll::handle_epoll_create1(a0 as i32)
        }
        SyscallNumber::EpollCtl => {
            crate::syscall::extended::epoll::handle_epoll_ctl(a0 as i32, a1 as i32, a2 as i32, a3)
        }
        SyscallNumber::EpollWait => {
            crate::syscall::extended::epoll::handle_epoll_wait(a0 as i32, a1, a2 as i32, a3 as i32)
        }
        SyscallNumber::EpollPwait => crate::syscall::extended::epoll::handle_epoll_pwait(
            a0 as i32, a1, a2 as i32, a3 as i32, a4, _a5,
        ),
        SyscallNumber::InotifyInit => crate::syscall::extended::inotify::handle_inotify_init(),
        SyscallNumber::InotifyInit1 => {
            crate::syscall::extended::inotify::handle_inotify_init1(a0 as i32)
        }
        SyscallNumber::InotifyAddWatch => {
            crate::syscall::extended::inotify::handle_inotify_add_watch(a0 as i32, a1, a2 as u32)
        }
        SyscallNumber::InotifyRmWatch => {
            crate::syscall::extended::inotify::handle_inotify_rm_watch(a0 as i32, a1 as i32)
        }
        SyscallNumber::Eventfd => crate::syscall::extended::eventfd_ops::handle_eventfd(a0 as u32),
        SyscallNumber::Eventfd2 => {
            crate::syscall::extended::eventfd_ops::handle_eventfd2(a0 as u32, a1 as i32)
        }
        SyscallNumber::Lseek => handle_lseek(a0 as i32, a1 as i64, a2 as i32),
        SyscallNumber::Ioctl => crate::syscall::extended::handle_ioctl(a0 as i32, a1, a2),
        SyscallNumber::Pread64 => {
            crate::syscall::extended::handle_pread64(a0 as i32, a1, a2, a3 as i64)
        }
        SyscallNumber::Pwrite64 => {
            crate::syscall::extended::handle_pwrite64(a0 as i32, a1, a2, a3 as i64)
        }
        SyscallNumber::Readv => crate::syscall::extended::handle_readv(a0 as i32, a1, a2 as i32),
        SyscallNumber::Writev => crate::syscall::extended::handle_writev(a0 as i32, a1, a2 as i32),
        SyscallNumber::Access => crate::syscall::extended::handle_access(a0, a1),
        SyscallNumber::Fcntl => crate::syscall::extended::handle_fcntl(a0 as i32, a1 as i32, a2),
        SyscallNumber::Ftruncate => crate::syscall::extended::handle_ftruncate(a0 as i32, a1),
        SyscallNumber::Truncate => crate::syscall::extended::handle_truncate(a0, a1),
        SyscallNumber::Creat => crate::syscall::extended::handle_creat(a0, a1),
        SyscallNumber::Readlink => crate::syscall::extended::handle_readlink(a0, a1, a2),
        SyscallNumber::Sendfile => {
            crate::syscall::extended::handle_sendfile(a0 as i32, a1 as i32, a2, a3)
        }
        SyscallNumber::Flock => crate::syscall::extended::handle_flock(a0 as i32, a1 as i32),
        SyscallNumber::Fsync => crate::syscall::extended::handle_fsync(a0 as i32),
        SyscallNumber::Fdatasync => crate::syscall::extended::handle_fdatasync(a0 as i32),
        SyscallNumber::Sync => crate::syscall::extended::handle_sync(),
        SyscallNumber::Syncfs => crate::syscall::extended::handle_syncfs(a0 as i32),
        SyscallNumber::Fallocate => {
            crate::syscall::extended::handle_fallocate(a0 as i32, a1 as i32, a2 as i64, a3 as i64)
        }
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
        SyscallNumber::Rmdir => handle_rmdir(a0),
        SyscallNumber::Mkdirat => crate::syscall::extended::handle_mkdirat(a0 as i32, a1, a2),
        SyscallNumber::Unlink => handle_unlink(a0),
        SyscallNumber::Unlinkat => {
            crate::syscall::extended::handle_unlinkat(a0 as i32, a1, a2 as i32)
        }
        SyscallNumber::Rename => handle_rename(a0, a1),
        SyscallNumber::Renameat => {
            crate::syscall::extended::handle_renameat(a0 as i32, a1, a2 as i32, a3)
        }
        SyscallNumber::Renameat2 => {
            crate::syscall::extended::handle_renameat2(a0 as i32, a1, a2 as i32, a3, a4 as u32)
        }
        SyscallNumber::Link => crate::syscall::extended::handle_link(a0, a1),
        SyscallNumber::Linkat => {
            crate::syscall::extended::handle_linkat(a0 as i32, a1, a2 as i32, a3, a4 as i32)
        }
        SyscallNumber::Symlink => crate::syscall::extended::handle_symlink(a0, a1),
        SyscallNumber::Symlinkat => crate::syscall::extended::handle_symlinkat(a0, a1 as i32, a2),
        SyscallNumber::Readlinkat => {
            crate::syscall::extended::handle_readlinkat(a0 as i32, a1, a2, a3)
        }
        SyscallNumber::FanotifyInit => dispatch_fanotify_init(a0 as u32, a1 as u32),
        SyscallNumber::FanotifyMark => {
            dispatch_fanotify_mark(a0 as i32, a1 as u32, a2, a3 as i32, a4 as usize)
        }
        SyscallNumber::ProcessVmReadv => {
            dispatch_process_vm_readv(a0 as i32, a1 as usize, a2 as usize, a3 as usize, a4 as usize)
        }
        SyscallNumber::ProcessVmWritev => dispatch_process_vm_writev(
            a0 as i32,
            a1 as usize,
            a2 as usize,
            a3 as usize,
            a4 as usize,
        ),
        SyscallNumber::SetRobustList => {
            crate::syscall::robust_futex::handle_set_robust_list(a0, a1)
        }
        SyscallNumber::GetRobustList => {
            crate::syscall::robust_futex::handle_get_robust_list(a0 as i32, a1, a2)
        }
        SyscallNumber::PkeyAlloc => crate::syscall::pkey::handle_pkey_alloc(a0, a1),
        SyscallNumber::PkeyFree => crate::syscall::pkey::handle_pkey_free(a0 as i32),
        SyscallNumber::PkeyMprotect => {
            crate::syscall::pkey::handle_pkey_mprotect(a0, a1, a2 as i32, a3 as i32)
        }
        SyscallNumber::Setxattr => {
            crate::syscall::xattr::handle_setxattr(a0, a1, a2, a3, a4 as i32)
        }
        SyscallNumber::Lsetxattr => {
            crate::syscall::xattr::handle_lsetxattr(a0, a1, a2, a3, a4 as i32)
        }
        SyscallNumber::Fsetxattr => {
            crate::syscall::xattr::handle_fsetxattr(a0 as i32, a1, a2, a3, a4 as i32)
        }
        SyscallNumber::Getxattr => crate::syscall::xattr::handle_getxattr(a0, a1, a2, a3),
        SyscallNumber::Lgetxattr => crate::syscall::xattr::handle_lgetxattr(a0, a1, a2, a3),
        SyscallNumber::Fgetxattr => crate::syscall::xattr::handle_fgetxattr(a0 as i32, a1, a2, a3),
        SyscallNumber::Listxattr => crate::syscall::xattr::handle_listxattr(a0, a1, a2),
        SyscallNumber::Llistxattr => crate::syscall::xattr::handle_llistxattr(a0, a1, a2),
        SyscallNumber::Flistxattr => crate::syscall::xattr::handle_flistxattr(a0 as i32, a1, a2),
        SyscallNumber::Removexattr => crate::syscall::xattr::handle_removexattr(a0, a1),
        SyscallNumber::Lremovexattr => crate::syscall::xattr::handle_lremovexattr(a0, a1),
        SyscallNumber::Fremovexattr => crate::syscall::xattr::handle_fremovexattr(a0 as i32, a1),
        SyscallNumber::Openat => {
            crate::syscall::extended::handle_openat(a0 as i32, a1, a2 as i32, a3 as u32)
        }
        SyscallNumber::Statfs => crate::syscall::extended::handle_statfs(a0, a1),
        SyscallNumber::Fstatfs => crate::syscall::extended::handle_fstatfs(a0 as i32, a1),
        SyscallNumber::Newfstatat => {
            crate::syscall::extended::handle_newfstatat(a0 as i32, a1, a2, a3 as i32)
        }
        SyscallNumber::Statx => {
            crate::syscall::extended::handle_statx(a0 as i32, a1, a2 as i32, a3 as u32, a4)
        }
        SyscallNumber::Getrandom => crate::syscall::extended::handle_getrandom(a0, a1, a2 as u32),
        SyscallNumber::MemfdCreate => crate::syscall::extended::handle_memfd_create(a0, a1 as u32),
        SyscallNumber::CopyFileRange => crate::syscall::extended::handle_copy_file_range(
            a0 as i32, a1, a2 as i32, a3, a4, _a5 as u32,
        ),
        SyscallNumber::Splice => {
            crate::syscall::extended::handle_splice(a0 as i32, a1, a2 as i32, a3, a4, _a5 as u32)
        }
        SyscallNumber::Tee => {
            crate::syscall::extended::handle_tee(a0 as i32, a1 as i32, a2, a3 as u32)
        }
        SyscallNumber::Vmsplice => {
            crate::syscall::extended::handle_vmsplice(a0 as i32, a1, a2, a3 as u32)
        }
        SyscallNumber::SyncFileRange => crate::syscall::extended::handle_sync_file_range(
            a0 as i32, a1 as i64, a2 as i64, a3 as u32,
        ),
        SyscallNumber::Fchownat => crate::syscall::extended::handle_fchownat(
            a0 as i32, a1, a2 as u32, a3 as u32, a4 as i32,
        ),
        SyscallNumber::Fchmodat => {
            crate::syscall::extended::handle_fchmodat(a0 as i32, a1, a2 as u32, a3 as i32)
        }
        SyscallNumber::Faccessat => {
            crate::syscall::extended::handle_faccessat(a0 as i32, a1, a2 as i32)
        }
        SyscallNumber::Chmod => crate::syscall::extended::handle_chmod(a0, a1 as u32),
        SyscallNumber::Fchmod => crate::syscall::extended::handle_fchmod(a0 as i32, a1 as u32),
        SyscallNumber::Chown => crate::syscall::extended::handle_chown(a0, a1 as u32, a2 as u32),
        SyscallNumber::Fchown => {
            crate::syscall::extended::handle_fchown(a0 as i32, a1 as u32, a2 as u32)
        }
        SyscallNumber::Lchown => crate::syscall::extended::handle_lchown(a0, a1 as u32, a2 as u32),
        SyscallNumber::Umask => crate::syscall::extended::handle_umask(a0 as u32),
        SyscallNumber::Mknod => crate::syscall::extended::handle_mknod(a0, a1 as u32, a2),
        SyscallNumber::Mknodat => {
            crate::syscall::extended::handle_mknodat(a0 as i32, a1, a2 as u32, a3)
        }
        SyscallNumber::Readahead => {
            crate::syscall::extended::handle_readahead(a0 as i32, a1 as i64, a2)
        }
        SyscallNumber::Fadvise64 => {
            crate::syscall::extended::handle_fadvise64(a0 as i32, a1 as i64, a2 as i64, a3 as i32)
        }
        SyscallNumber::IoSetup => crate::syscall::aio::handle_io_setup(a0 as u32, a1),
        SyscallNumber::IoDestroy => crate::syscall::aio::handle_io_destroy(a0),
        SyscallNumber::IoSubmit => crate::syscall::aio::handle_io_submit(a0, a1 as i64, a2),
        SyscallNumber::IoGetevents => {
            crate::syscall::aio::handle_io_getevents(a0, a1 as i64, a2 as i64, a3, a4)
        }
        SyscallNumber::IoCancel => crate::syscall::aio::handle_io_cancel(a0, a1, a2),
        SyscallNumber::Bpf => crate::syscall::bpf::handle_bpf(a0 as u32, a1, a2 as u32),
        // The Linux-shaped keyring surface is gated behind
        // `nonos-syscall-keyring`. The live keyring authority is the
        // userland capsule under `crate::security::keyring_capsule`;
        // these arms exist only for legacy callers and fall through
        // to ENOSYS in every production profile.
        #[cfg(feature = "nonos-syscall-keyring")]
        SyscallNumber::AddKey => crate::syscall::keyring::handle_add_key(a0, a1, a2, a3, a4 as i32),
        #[cfg(feature = "nonos-syscall-keyring")]
        SyscallNumber::RequestKey => {
            crate::syscall::keyring::handle_request_key(a0, a1, a2, a3 as i32)
        }
        #[cfg(feature = "nonos-syscall-keyring")]
        SyscallNumber::Keyctl => crate::syscall::keyring::handle_keyctl(a0 as u32, a1, a2, a3, a4),
        _ => errno(38),
    }
}

fn dispatch_fanotify_init(flags: u32, event_f_flags: u32) -> SyscallResult {
    let result = crate::syscall::fanotify::sys_fanotify_init(flags, event_f_flags);
    SyscallResult { value: result, capability_consumed: false, audit_required: true }
}

fn dispatch_fanotify_mark(
    fd: i32,
    flags: u32,
    mask: u64,
    dirfd: i32,
    pathname: usize,
) -> SyscallResult {
    let result = crate::syscall::fanotify::sys_fanotify_mark(fd, flags, mask, dirfd, pathname);
    SyscallResult { value: result, capability_consumed: false, audit_required: true }
}

fn dispatch_process_vm_readv(
    pid: i32,
    lvec: usize,
    liovcnt: usize,
    rvec: usize,
    riovcnt: usize,
) -> SyscallResult {
    let result =
        crate::syscall::process_vm::sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, 0);
    SyscallResult { value: result, capability_consumed: false, audit_required: true }
}

fn dispatch_process_vm_writev(
    pid: i32,
    lvec: usize,
    liovcnt: usize,
    rvec: usize,
    riovcnt: usize,
) -> SyscallResult {
    let result =
        crate::syscall::process_vm::sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, 0);
    SyscallResult { value: result, capability_consumed: false, audit_required: true }
}
