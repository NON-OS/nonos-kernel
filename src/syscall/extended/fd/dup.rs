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

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

static NEXT_FD: AtomicU32 = AtomicU32::new(1000);
static FD_DUP_TABLE: Mutex<BTreeMap<u32, u32>> = Mutex::new(BTreeMap::new());

fn allocate_fd() -> u32 {
    NEXT_FD.fetch_add(1, Ordering::SeqCst)
}

pub fn handle_dup(oldfd: u64) -> SyscallResult {
    if oldfd > u32::MAX as u64 {
        return errno(9);
    }

    let oldfd = oldfd as u32;

    if oldfd < 3 {
    } else {
        let exists = crate::fs::nonos_vfs::vfs_fd_exists(oldfd);
        if !exists {
            return errno(9);
        }
    }

    let newfd = allocate_fd();
    FD_DUP_TABLE.lock().insert(newfd, oldfd);

    SyscallResult { value: newfd as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_dup2(oldfd: u64, newfd: u64) -> SyscallResult {
    if oldfd > u32::MAX as u64 || newfd > u32::MAX as u64 {
        return errno(9);
    }

    let oldfd = oldfd as u32;
    let newfd = newfd as u32;

    if oldfd == newfd {
        return SyscallResult { value: newfd as i64, capability_consumed: false, audit_required: false };
    }

    if oldfd >= 3 {
        let exists = crate::fs::nonos_vfs::vfs_fd_exists(oldfd);
        if !exists && !FD_DUP_TABLE.lock().contains_key(&oldfd) {
            return errno(9);
        }
    }

    if newfd >= 3 {
        let _ = crate::fs::nonos_vfs::vfs_close(newfd);
        FD_DUP_TABLE.lock().remove(&newfd);
    }

    FD_DUP_TABLE.lock().insert(newfd, oldfd);

    SyscallResult { value: newfd as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_dup3(oldfd: u64, newfd: u64, _flags: u64) -> SyscallResult {
    if oldfd == newfd {
        return errno(22);
    }
    handle_dup2(oldfd, newfd)
}

pub fn handle_pipe(pipefd: u64) -> SyscallResult {
    if pipefd == 0 {
        return errno(14);
    }

    let read_fd = allocate_fd();
    let write_fd = allocate_fd();

    unsafe {
        core::ptr::write(pipefd as *mut u32, read_fd);
        core::ptr::write((pipefd + 4) as *mut u32, write_fd);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_pipe2(pipefd: u64, _flags: u64) -> SyscallResult {
    handle_pipe(pipefd)
}
