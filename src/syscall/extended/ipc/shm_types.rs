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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use super::super::errno;
use super::constants::*;
use crate::syscall::SyscallResult;

pub fn ok(value: i64) -> SyscallResult {
    SyscallResult { value, capability_consumed: false, audit_required: false }
}

#[derive(Clone)]
pub struct ShmSegment {
    pub key: u64,
    pub size: usize,
    pub flags: i32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub atime: u64,
    pub dtime: u64,
    pub ctime: u64,
    pub cpid: u32,
    pub lpid: u32,
    pub nattch: u32,
    pub data: Vec<u8>,
    pub marked_for_removal: bool,
}

pub static SHM_SEGMENTS: Mutex<BTreeMap<i32, ShmSegment>> = Mutex::new(BTreeMap::new());
pub static SHM_NEXT_ID: AtomicI32 = AtomicI32::new(1);
pub static SHM_ATTACHMENTS: Mutex<BTreeMap<(u32, u64), i32>> = Mutex::new(BTreeMap::new());

pub fn handle_shmget(key: u64, size: u64, shmflg: i32) -> SyscallResult {
    let size = size as usize;
    if size < SHMMIN || size > SHMMAX {
        return errno(22);
    }
    let mut segments = SHM_SEGMENTS.lock();
    if key != IPC_PRIVATE {
        for (&id, seg) in segments.iter() {
            if seg.key == key {
                if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                    return errno(17);
                }
                return ok(id as i64);
            }
        }
    }
    if key != IPC_PRIVATE && (shmflg & IPC_CREAT) == 0 {
        return errno(2);
    }
    if segments.len() >= SHMMNI {
        return errno(28);
    }
    let id = SHM_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let pid = crate::process::current_pid().unwrap_or(0);
    let segment = ShmSegment {
        key,
        size,
        flags: shmflg,
        mode: (shmflg & 0o777) as u16,
        uid: 0,
        gid: 0,
        cuid: 0,
        cgid: 0,
        atime: 0,
        dtime: 0,
        ctime: crate::time::timestamp_millis(),
        cpid: pid,
        lpid: 0,
        nattch: 0,
        data: alloc::vec![0u8; size],
        marked_for_removal: false,
    };
    segments.insert(id, segment);
    ok(id as i64)
}
