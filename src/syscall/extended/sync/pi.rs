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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::super::errno;
use super::constants::*;
use super::helpers::wake_futex;
use super::types::{ok, FUTEX_WAITER_MAP, FUTEX_WAKES, PI_OWNERS};
use super::wait_wake::handle_futex_wait;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub(super) fn handle_futex_lock_pi(uaddr: u64, timeout: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    let current: u32 = match read_user_value(uaddr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };

    if current == 0 {
        if write_user_value(uaddr, &pid).is_err() {
            return errno(14);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    if (current & FUTEX_OWNER_DIED) != 0 {
        let new_val = pid | (current & FUTEX_WAITERS);
        if write_user_value(uaddr, &new_val).is_err() {
            return errno(14);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    let owner_tid = current & FUTEX_TID_MASK;
    if owner_tid == pid {
        return errno(35);
    }

    let with_waiters = current | FUTEX_WAITERS;
    if write_user_value(uaddr, &with_waiters).is_err() {
        return errno(14);
    }

    handle_futex_wait(uaddr, with_waiters as u64, timeout, FUTEX_BITSET_MATCH_ANY, true)
}

pub(super) fn handle_futex_unlock_pi(uaddr: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    let current: u32 = match read_user_value(uaddr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let owner_tid = current & FUTEX_TID_MASK;

    if owner_tid != pid {
        return errno(1);
    }

    if (current & FUTEX_WAITERS) != 0 {
        wake_futex(uaddr, 1, FUTEX_BITSET_MATCH_ANY);
    }

    let zero: u32 = 0;
    if write_user_value(uaddr, &zero).is_err() {
        return errno(14);
    }
    PI_OWNERS.lock().remove(&uaddr);

    ok(0)
}

pub(super) fn handle_futex_trylock_pi(uaddr: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    let current: u32 = match read_user_value(uaddr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };

    if current == 0 {
        if write_user_value(uaddr, &pid).is_err() {
            return errno(14);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    if (current & FUTEX_OWNER_DIED) != 0 {
        let new_val = pid | (current & FUTEX_WAITERS);
        if write_user_value(uaddr, &new_val).is_err() {
            return errno(14);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    errno(11)
}

pub(super) fn handle_futex_wait_requeue_pi(
    uaddr: u64,
    val: u64,
    timeout: u64,
    uaddr2: u64,
    _val3: u64,
) -> SyscallResult {
    if uaddr2 == 0 || (uaddr2 & 3) != 0 {
        return errno(14);
    }

    let current: u32 = match read_user_value(uaddr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if current != val as u32 {
        return errno(11);
    }

    handle_futex_wait(uaddr, val, timeout, FUTEX_BITSET_MATCH_ANY, true)
}

pub(super) fn handle_futex_cmp_requeue_pi(
    uaddr: u64,
    val: u64,
    val2: u64,
    uaddr2: u64,
    val3: u64,
) -> SyscallResult {
    if uaddr2 == 0 || (uaddr2 & 3) != 0 {
        return errno(14);
    }

    let current: u32 = match read_user_value(uaddr) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if current != val3 as u32 {
        return errno(11);
    }

    let (woken, requeued) = requeue_waiters(uaddr, uaddr2, val as usize, val2 as usize);

    if requeued > 0 {
        set_waiters_flag_if_needed(uaddr2);
    }

    FUTEX_WAKES.fetch_add(woken as u64, Ordering::Relaxed);
    ok(woken as i64)
}

fn requeue_waiters(uaddr: u64, uaddr2: u64, max_wake: usize, max_requeue: usize) -> (usize, usize) {
    let mut woken = 0;
    let mut requeued = 0;
    let mut waiters_guard = FUTEX_WAITER_MAP.lock();
    let mut waiters_to_requeue = Vec::new();

    if let Some(waiters) = waiters_guard.get_mut(&uaddr) {
        while woken < max_wake && !waiters.is_empty() {
            waiters.remove(0);
            woken += 1;
        }
        while requeued < max_requeue && !waiters.is_empty() {
            let mut waiter = waiters.remove(0);
            waiter.is_pi = true;
            waiters_to_requeue.push(waiter);
            requeued += 1;
        }
    }

    for waiter in waiters_to_requeue {
        waiters_guard.entry(uaddr2).or_insert_with(Vec::new).push(waiter);
    }

    (woken, requeued)
}

fn set_waiters_flag_if_needed(uaddr2: u64) {
    let current: u32 = match read_user_value(uaddr2) {
        Ok(v) => v,
        Err(_) => return,
    };
    if (current & FUTEX_WAITERS) == 0 && current != 0 {
        let new_val = current | FUTEX_WAITERS;
        let _ = write_user_value(uaddr2, &new_val);
    }
}
