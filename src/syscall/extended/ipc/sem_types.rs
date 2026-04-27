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
pub struct Semaphore {
    pub value: i16,
    pub sempid: u32,
    pub semncnt: u16,
    pub semzcnt: u16,
}

#[derive(Clone)]
pub struct SemaphoreSet {
    pub key: u64,
    pub nsems: usize,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub ctime: u64,
    pub otime: u64,
    pub sems: Vec<Semaphore>,
}

pub static SEM_SETS: Mutex<BTreeMap<i32, SemaphoreSet>> = Mutex::new(BTreeMap::new());
pub static SEM_NEXT_ID: AtomicI32 = AtomicI32::new(1);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

pub fn handle_semget(key: u64, nsems: i32, semflg: i32) -> SyscallResult {
    let nsems = nsems as usize;
    if nsems > SEMMSL {
        return errno(22);
    }
    let mut sets = SEM_SETS.lock();
    if key != IPC_PRIVATE {
        for (&id, set) in sets.iter() {
            if set.key == key {
                if (semflg & IPC_CREAT) != 0 && (semflg & IPC_EXCL) != 0 {
                    return errno(17);
                }
                if nsems > 0 && nsems > set.nsems {
                    return errno(22);
                }
                return ok(id as i64);
            }
        }
    }
    if key != IPC_PRIVATE && (semflg & IPC_CREAT) == 0 {
        return errno(2);
    }
    if nsems == 0 {
        return errno(22);
    }
    if sets.len() >= SEMMNI {
        return errno(28);
    }
    let id = SEM_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let set = SemaphoreSet {
        key,
        nsems,
        mode: (semflg & 0o777) as u16,
        uid: 0,
        gid: 0,
        ctime: crate::time::timestamp_millis(),
        otime: 0,
        sems: (0..nsems)
            .map(|_| Semaphore { value: 0, sempid: 0, semncnt: 0, semzcnt: 0 })
            .collect(),
    };
    sets.insert(id, set);
    ok(id as i64)
}
