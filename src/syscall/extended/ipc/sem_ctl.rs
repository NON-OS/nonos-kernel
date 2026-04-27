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

use super::super::errno;
use super::constants::*;
use super::sem_types::{ok, SEM_SETS};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

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
        IPC_STAT | SEM_STAT => handle_sem_stat(&sets, semid, arg),
        GETVAL => handle_getval(&sets, semid, semnum),
        SETVAL => handle_setval(&mut sets, semid, semnum, arg),
        GETPID => handle_getpid(&sets, semid, semnum),
        GETNCNT => handle_getncnt(&sets, semid, semnum),
        GETZCNT => handle_getzcnt(&sets, semid, semnum),
        GETALL => handle_getall(&sets, semid, arg),
        SETALL => handle_setall(&mut sets, semid, arg),
        _ => errno(22),
    }
}

fn handle_sem_stat(
    sets: &alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    arg: u64,
) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    if let Some(set) = sets.get(&semid) {
        let mut buf = [0u8; 56];
        buf[0..8].copy_from_slice(&set.key.to_ne_bytes());
        buf[8..16].copy_from_slice(&(set.uid as u64).to_ne_bytes());
        buf[16..24].copy_from_slice(&(set.gid as u64).to_ne_bytes());
        buf[24..32].copy_from_slice(&(set.mode as u64).to_ne_bytes());
        buf[32..40].copy_from_slice(&(set.nsems as u64).to_ne_bytes());
        buf[40..48].copy_from_slice(&set.otime.to_ne_bytes());
        buf[48..56].copy_from_slice(&set.ctime.to_ne_bytes());
        if copy_to_user(arg, &buf).is_err() {
            return errno(14);
        }
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_getval(
    sets: &alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    semnum: i32,
) -> SyscallResult {
    if let Some(set) = sets.get(&semid) {
        if semnum < 0 || semnum as usize >= set.nsems {
            return errno(22);
        }
        ok(set.sems[semnum as usize].value as i64)
    } else {
        errno(22)
    }
}

fn handle_setval(
    sets: &mut alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    semnum: i32,
    arg: u64,
) -> SyscallResult {
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

fn handle_getpid(
    sets: &alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    semnum: i32,
) -> SyscallResult {
    if let Some(set) = sets.get(&semid) {
        if semnum < 0 || semnum as usize >= set.nsems {
            return errno(22);
        }
        ok(set.sems[semnum as usize].sempid as i64)
    } else {
        errno(22)
    }
}

fn handle_getncnt(
    sets: &alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    semnum: i32,
) -> SyscallResult {
    if let Some(set) = sets.get(&semid) {
        if semnum < 0 || semnum as usize >= set.nsems {
            return errno(22);
        }
        ok(set.sems[semnum as usize].semncnt as i64)
    } else {
        errno(22)
    }
}

fn handle_getzcnt(
    sets: &alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    semnum: i32,
) -> SyscallResult {
    if let Some(set) = sets.get(&semid) {
        if semnum < 0 || semnum as usize >= set.nsems {
            return errno(22);
        }
        ok(set.sems[semnum as usize].semzcnt as i64)
    } else {
        errno(22)
    }
}

fn handle_getall(
    sets: &alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    arg: u64,
) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    if let Some(set) = sets.get(&semid) {
        let vals: alloc::vec::Vec<u16> = set.sems.iter().map(|s| s.value as u16).collect();
        let bytes: alloc::vec::Vec<u8> = vals.iter().flat_map(|v| v.to_ne_bytes()).collect();
        if copy_to_user(arg, &bytes).is_err() {
            return errno(14);
        }
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_setall(
    sets: &mut alloc::collections::BTreeMap<i32, super::sem_types::SemaphoreSet>,
    semid: i32,
    arg: u64,
) -> SyscallResult {
    if arg == 0 {
        return errno(14);
    }
    if let Some(set) = sets.get_mut(&semid) {
        let pid = crate::process::current_pid().unwrap_or(0);
        let buf_size = match set.nsems.checked_mul(2) {
            Some(v) => v,
            None => return errno(22),
        };
        let mut buf = alloc::vec![0u8; buf_size];
        if copy_from_user(arg, &mut buf).is_err() {
            return errno(14);
        }
        for (i, sem) in set.sems.iter_mut().enumerate() {
            let off = match i.checked_mul(2) {
                Some(v) => v,
                None => break,
            };
            if let (Some(&b0), Some(&b1)) = (buf.get(off), buf.get(off + 1)) {
                sem.value = u16::from_ne_bytes([b0, b1]) as i16;
                sem.sempid = pid;
            }
        }
        set.ctime = crate::time::timestamp_millis();
        ok(0)
    } else {
        errno(22)
    }
}
