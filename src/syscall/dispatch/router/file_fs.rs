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

use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::file_io::*;
use crate::syscall::dispatch::util::errno;

pub(super) fn dispatch_file_fs(syscall: SyscallNumber, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, _a5: u64) -> SyscallResult {
    match syscall {
        SyscallNumber::Read => handle_read(a0 as i32, a1, a2), SyscallNumber::Write => handle_write(a0 as i32, a1, a2),
        SyscallNumber::Open => handle_open(a0, a1, a2), SyscallNumber::Close => handle_close(a0 as i32),
        SyscallNumber::Stat => handle_stat(a0, a1), SyscallNumber::Fstat => handle_fstat(a0 as i32, a1),
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
        SyscallNumber::Mkdir => handle_mkdir(a0, a1), SyscallNumber::Rmdir => handle_rmdir(a0),
        SyscallNumber::Mkdirat => crate::syscall::extended::handle_mkdirat(a0 as i32, a1, a2),
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
        _ => errno(38),
    }
}
