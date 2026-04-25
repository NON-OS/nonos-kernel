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
use super::sem_types::{ok, Sembuf, SEM_SETS};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, read_user_value};
use alloc::vec::Vec;

pub fn handle_semop(semid: i32, sops: u64, nsops: u64) -> SyscallResult {
    handle_semtimedop(semid, sops, nsops, 0)
}

pub fn handle_semtimedop(semid: i32, sops: u64, nsops: u64, timeout: u64) -> SyscallResult {
    if sops == 0 || nsops == 0 || nsops as usize > SEMOPM {
        return errno(22);
    }
    let deadline = if timeout != 0 {
        let ts_sec: i64 = match read_user_value(timeout) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let timeout_off = match timeout.checked_add(8) {
            Some(v) => v,
            None => return errno(14),
        };
        let ts_nsec: i64 = match read_user_value(timeout_off) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let now = crate::time::timestamp_millis();
        let sec_ms = (ts_sec as u64).saturating_mul(1000);
        now.saturating_add(sec_ms).saturating_add((ts_nsec as u64) / 1_000_000)
    } else {
        u64::MAX
    };
    let pid = crate::process::current_pid().unwrap_or(0);
    let ops = match read_sembuf_array(sops, nsops as usize) {
        Ok(o) => o,
        Err(e) => return e,
    };
    loop {
        let mut sets = SEM_SETS.lock();
        let set = match sets.get_mut(&semid) {
            Some(s) => s,
            None => return errno(22),
        };
        let can_proceed = match check_sem_ops(set, &ops) {
            Ok(c) => c,
            Err(e) => return e,
        };
        if can_proceed {
            apply_sem_ops(set, &ops, pid);
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

fn read_sembuf_array(sops: u64, nsops: usize) -> Result<Vec<Sembuf>, SyscallResult> {
    let buf_size = match nsops.checked_mul(6) {
        Some(v) => v,
        None => return Err(errno(22)),
    };
    let mut buf = alloc::vec![0u8; buf_size];
    if copy_from_user(sops, &mut buf).is_err() {
        return Err(errno(14));
    }
    let ops: Vec<Sembuf> = (0..nsops)
        .filter_map(|i| {
            let offset = i.checked_mul(6)?;
            Some(Sembuf {
                sem_num: u16::from_ne_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]),
                sem_op: i16::from_ne_bytes([*buf.get(offset + 2)?, *buf.get(offset + 3)?]),
                sem_flg: i16::from_ne_bytes([*buf.get(offset + 4)?, *buf.get(offset + 5)?]),
            })
        })
        .collect();
    Ok(ops)
}

fn check_sem_ops(
    set: &super::sem_types::SemaphoreSet,
    ops: &[Sembuf],
) -> Result<bool, SyscallResult> {
    for op in ops {
        if op.sem_num as usize >= set.nsems {
            return Err(errno(22));
        }
        let sem = &set.sems[op.sem_num as usize];
        let new_val = sem.value as i32 + op.sem_op as i32;
        if op.sem_op < 0 && new_val < 0 {
            return Ok(false);
        }
        if op.sem_op == 0 && sem.value != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn apply_sem_ops(set: &mut super::sem_types::SemaphoreSet, ops: &[Sembuf], pid: u32) {
    for op in ops {
        let sem = &mut set.sems[op.sem_num as usize];
        let new_val = (sem.value as i32).saturating_add(op.sem_op as i32);
        sem.value = new_val.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        sem.sempid = pid;
    }
    set.otime = crate::time::timestamp_millis();
}
