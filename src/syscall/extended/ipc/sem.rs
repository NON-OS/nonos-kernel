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

use crate::syscall::SyscallResult;
use super::super::errno;
use super::constants::*;

fn ok(value: i64) -> SyscallResult {
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
struct Sembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
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
    let now = crate::time::timestamp_millis();

    let set = SemaphoreSet {
        key,
        nsems,
        mode: (semflg & 0o777) as u16,
        uid: 0,
        gid: 0,
        ctime: now,
        otime: 0,
        sems: (0..nsems).map(|_| Semaphore {
            value: 0,
            sempid: 0,
            semncnt: 0,
            semzcnt: 0,
        }).collect(),
    };

    sets.insert(id, set);
    ok(id as i64)
}

pub fn handle_semop(semid: i32, sops: u64, nsops: u64) -> SyscallResult {
    handle_semtimedop(semid, sops, nsops, 0)
}

pub fn handle_semtimedop(semid: i32, sops: u64, nsops: u64, timeout: u64) -> SyscallResult {
    if sops == 0 || nsops == 0 || nsops as usize > SEMOPM {
        return errno(22);
    }

    let deadline = if timeout != 0 {
        // SAFETY: timeout is user-provided pointer to timespec.
        unsafe {
            let ts_sec = core::ptr::read(timeout as *const i64);
            let ts_nsec = core::ptr::read((timeout + 8) as *const i64);
            let now = crate::time::timestamp_millis();
            now.saturating_add((ts_sec as u64) * 1000).saturating_add((ts_nsec as u64) / 1_000_000)
        }
    } else {
        u64::MAX
    };

    let pid = crate::process::current_pid().unwrap_or(0);

    // SAFETY: sops is user-provided pointer to array of sembuf.
    let ops: Vec<Sembuf> = unsafe {
        let ptr = sops as *const Sembuf;
        (0..nsops as usize).map(|i| core::ptr::read(ptr.add(i))).collect()
    };

    loop {
        let mut sets = SEM_SETS.lock();

        let set = match sets.get_mut(&semid) {
            Some(s) => s,
            None => return errno(22),
        };

        let mut can_proceed = true;
        for op in &ops {
            if op.sem_num as usize >= set.nsems {
                return errno(22);
            }

            let sem = &set.sems[op.sem_num as usize];
            let new_val = sem.value as i32 + op.sem_op as i32;

            if op.sem_op < 0 && new_val < 0 {
                can_proceed = false;
                break;
            }
            if op.sem_op == 0 && sem.value != 0 {
                can_proceed = false;
                break;
            }
        }

        if can_proceed {
            for op in &ops {
                let sem = &mut set.sems[op.sem_num as usize];
                sem.value = (sem.value as i32 + op.sem_op as i32) as i16;
                sem.sempid = pid;
            }
            set.otime = crate::time::timestamp_millis();
            return ok(0);
        }

        drop(sets);

        if ops.iter().any(|op| (op.sem_flg & IPC_NOWAIT as i16) != 0) {
            return errno(11);
        }

        if crate::time::timestamp_millis() >= deadline {
            return errno(11);
        }

        crate::sched::yield_cpu();
    }
}

pub fn handle_semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> SyscallResult {
    let mut sets = SEM_SETS.lock();

    match cmd {
        IPC_RMID => {
            if sets.remove(&semid).is_some() {
                ok(0)
            } else {
                errno(22)
            }
        }
        IPC_STAT | SEM_STAT => {
            if arg == 0 {
                return errno(14);
            }
            if let Some(set) = sets.get(&semid) {
                // SAFETY: arg is user-provided pointer for semid_ds struct.
                unsafe {
                    let ptr = arg as *mut u64;
                    core::ptr::write(ptr.add(0), set.key);
                    core::ptr::write(ptr.add(1), set.uid as u64);
                    core::ptr::write(ptr.add(2), set.gid as u64);
                    core::ptr::write(ptr.add(3), set.mode as u64);
                    core::ptr::write(ptr.add(4), set.nsems as u64);
                    core::ptr::write(ptr.add(5), set.otime);
                    core::ptr::write(ptr.add(6), set.ctime);
                }
                ok(0)
            } else {
                errno(22)
            }
        }
        GETVAL => {
            if let Some(set) = sets.get(&semid) {
                if semnum < 0 || semnum as usize >= set.nsems {
                    return errno(22);
                }
                ok(set.sems[semnum as usize].value as i64)
            } else {
                errno(22)
            }
        }
        SETVAL => {
            if let Some(set) = sets.get_mut(&semid) {
                if semnum < 0 || semnum as usize >= set.nsems {
                    return errno(22);
                }
                set.sems[semnum as usize].value = arg as i16;
                set.sems[semnum as usize].sempid = crate::process::current_pid().unwrap_or(0);
                set.ctime = crate::time::timestamp_millis();
                ok(0)
            } else {
                errno(22)
            }
        }
        GETPID => {
            if let Some(set) = sets.get(&semid) {
                if semnum < 0 || semnum as usize >= set.nsems {
                    return errno(22);
                }
                ok(set.sems[semnum as usize].sempid as i64)
            } else {
                errno(22)
            }
        }
        GETNCNT => {
            if let Some(set) = sets.get(&semid) {
                if semnum < 0 || semnum as usize >= set.nsems {
                    return errno(22);
                }
                ok(set.sems[semnum as usize].semncnt as i64)
            } else {
                errno(22)
            }
        }
        GETZCNT => {
            if let Some(set) = sets.get(&semid) {
                if semnum < 0 || semnum as usize >= set.nsems {
                    return errno(22);
                }
                ok(set.sems[semnum as usize].semzcnt as i64)
            } else {
                errno(22)
            }
        }
        GETALL => {
            if arg == 0 {
                return errno(14);
            }
            if let Some(set) = sets.get(&semid) {
                // SAFETY: arg is user-provided pointer for semaphore values.
                unsafe {
                    let ptr = arg as *mut u16;
                    for (i, sem) in set.sems.iter().enumerate() {
                        core::ptr::write(ptr.add(i), sem.value as u16);
                    }
                }
                ok(0)
            } else {
                errno(22)
            }
        }
        SETALL => {
            if arg == 0 {
                return errno(14);
            }
            if let Some(set) = sets.get_mut(&semid) {
                let pid = crate::process::current_pid().unwrap_or(0);
                // SAFETY: arg is user-provided pointer for semaphore values.
                unsafe {
                    let ptr = arg as *const u16;
                    for (i, sem) in set.sems.iter_mut().enumerate() {
                        sem.value = core::ptr::read(ptr.add(i)) as i16;
                        sem.sempid = pid;
                    }
                }
                set.ctime = crate::time::timestamp_millis();
                ok(0)
            } else {
                errno(22)
            }
        }
        _ => errno(22),
    }
}
