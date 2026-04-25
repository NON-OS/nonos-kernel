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

use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use alloc::collections::BTreeMap;
use spin::Mutex;

const LOCK_SH: i32 = 1;
const LOCK_EX: i32 = 2;
const LOCK_UN: i32 = 8;
const LOCK_NB: i32 = 4;

#[derive(Debug, Clone, Copy, PartialEq)]
enum LockType {
    None,
    Shared,
    Exclusive,
}

struct FileLock {
    lock_type: LockType,
    holder_count: u32,
}

static FILE_LOCKS: Mutex<BTreeMap<u64, FileLock>> = Mutex::new(BTreeMap::new());

/* DEV NOTES eK@nonos.systems
   File locking implementation using advisory locks. LOCK_SH allows multiple readers,
   LOCK_EX is exclusive. LOCK_NB makes the operation non-blocking. Uses path hash
   as file identifier since ramfs doesn't have inode numbers.
*/
pub fn handle_flock(fd: i32, operation: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    let path = match crate::fs::fd::fd_get_path(fd) {
        Ok(p) => p,
        Err(_) => return errno(9),
    };

    let file_id = hash_path(&path);
    let op = operation & !LOCK_NB;
    let non_blocking = (operation & LOCK_NB) != 0;

    let mut locks = FILE_LOCKS.lock();

    match op {
        LOCK_UN => {
            if let Some(lock) = locks.get_mut(&file_id) {
                if lock.holder_count > 1 {
                    lock.holder_count -= 1;
                } else {
                    locks.remove(&file_id);
                }
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        LOCK_SH => {
            if let Some(lock) = locks.get_mut(&file_id) {
                if lock.lock_type == LockType::Exclusive {
                    if non_blocking {
                        return errno(11);
                    }
                    return errno(11);
                }
                lock.holder_count += 1;
            } else {
                locks.insert(file_id, FileLock { lock_type: LockType::Shared, holder_count: 1 });
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        LOCK_EX => {
            if let Some(lock) = locks.get(&file_id) {
                if lock.lock_type != LockType::None {
                    if non_blocking {
                        return errno(11);
                    }
                    return errno(11);
                }
            }
            locks.insert(file_id, FileLock { lock_type: LockType::Exclusive, holder_count: 1 });
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        _ => errno(22),
    }
}

fn hash_path(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in path.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn handle_fsync(fd: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    match crate::fs::fd::fd_sync(fd) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(5),
    }
}

pub fn handle_fdatasync(fd: i32) -> SyscallResult {
    handle_fsync(fd)
}

pub fn handle_sync() -> SyscallResult {
    let _ = crate::fs::sync_all();
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_syncfs(fd: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    let _ = crate::fs::sync_all();
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if offset < 0 || len <= 0 {
        return errno(22);
    }

    let _ = mode;

    match crate::fs::fd::fd_allocate(fd, offset as usize, len as usize) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(28),
    }
}
