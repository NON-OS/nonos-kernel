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

use crate::capabilities::CapabilityToken;
use crate::syscall::numbers::SyscallNumber;

pub(super) fn check(caps: &CapabilityToken, number: SyscallNumber) -> Option<bool> {
    Some(match number {
        SyscallNumber::Read
        | SyscallNumber::Pread64
        | SyscallNumber::Readv
        | SyscallNumber::Preadv
        | SyscallNumber::Preadv2
        | SyscallNumber::Poll
        | SyscallNumber::Ppoll
        | SyscallNumber::Select
        | SyscallNumber::Pselect6
        | SyscallNumber::Ioctl
        | SyscallNumber::Fcntl
        | SyscallNumber::Readlink
        | SyscallNumber::Readlinkat
        | SyscallNumber::Sendfile
        | SyscallNumber::CopyFileRange
        | SyscallNumber::Splice
        | SyscallNumber::Tee
        | SyscallNumber::Vmsplice
        | SyscallNumber::Getdents
        | SyscallNumber::Getdents64
        | SyscallNumber::Fadvise64
        | SyscallNumber::Readahead
        | SyscallNumber::Getxattr
        | SyscallNumber::Lgetxattr
        | SyscallNumber::Fgetxattr
        | SyscallNumber::Listxattr
        | SyscallNumber::Llistxattr
        | SyscallNumber::Flistxattr
        | SyscallNumber::Sysfs => caps.can_read(),

        SyscallNumber::Write
        | SyscallNumber::Pwrite64
        | SyscallNumber::Writev
        | SyscallNumber::Pwritev
        | SyscallNumber::Pwritev2
        | SyscallNumber::Ftruncate
        | SyscallNumber::Truncate
        | SyscallNumber::Fallocate
        | SyscallNumber::Flock
        | SyscallNumber::Fsync
        | SyscallNumber::Fdatasync
        | SyscallNumber::Sync
        | SyscallNumber::Syncfs
        | SyscallNumber::SyncFileRange
        | SyscallNumber::Utime
        | SyscallNumber::Utimes
        | SyscallNumber::Utimensat
        | SyscallNumber::Futimesat
        | SyscallNumber::Setxattr
        | SyscallNumber::Lsetxattr
        | SyscallNumber::Fsetxattr
        | SyscallNumber::Removexattr
        | SyscallNumber::Lremovexattr
        | SyscallNumber::Fremovexattr => caps.can_write(),

        SyscallNumber::Open | SyscallNumber::Openat | SyscallNumber::Creat
        | SyscallNumber::Pipe | SyscallNumber::Pipe2
        | SyscallNumber::NameToHandleAt | SyscallNumber::OpenByHandleAt => caps.can_open_files(),

        SyscallNumber::Close => caps.can_close_files(),

        SyscallNumber::Stat
        | SyscallNumber::Fstat
        | SyscallNumber::Lstat
        | SyscallNumber::Newfstatat
        | SyscallNumber::Statx
        | SyscallNumber::Access
        | SyscallNumber::Faccessat
        | SyscallNumber::Statfs
        | SyscallNumber::Fstatfs
        | SyscallNumber::Chdir
        | SyscallNumber::Fchdir => caps.can_stat(),

        SyscallNumber::Lseek => caps.can_seek(),

        SyscallNumber::Mkdir
        | SyscallNumber::Mkdirat
        | SyscallNumber::Rmdir
        | SyscallNumber::Rename
        | SyscallNumber::Renameat
        | SyscallNumber::Renameat2
        | SyscallNumber::Link
        | SyscallNumber::Linkat
        | SyscallNumber::Symlink
        | SyscallNumber::Symlinkat
        | SyscallNumber::Chmod
        | SyscallNumber::Fchmod
        | SyscallNumber::Fchmodat
        | SyscallNumber::Chown
        | SyscallNumber::Fchown
        | SyscallNumber::Lchown
        | SyscallNumber::Fchownat
        | SyscallNumber::Mknod
        | SyscallNumber::Mknodat => caps.can_modify_dirs(),

        SyscallNumber::Unlink | SyscallNumber::Unlinkat => caps.can_unlink(),

        SyscallNumber::Dup | SyscallNumber::Dup2 | SyscallNumber::Dup3
        | SyscallNumber::Getcwd | SyscallNumber::RestartSyscall => caps.is_valid(),

        SyscallNumber::Chroot | SyscallNumber::Mount | SyscallNumber::Umount2 => caps.can_admin(),

        _ => return None,
    })
}
