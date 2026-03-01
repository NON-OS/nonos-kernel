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

use super::constants::*;
use super::helpers::wake_futex;
use super::wait_wake::handle_futex_wait;
use super::types::{ok, FUTEX_WAITER_MAP, PI_OWNERS, FUTEX_WAKES};
use crate::syscall::SyscallResult;
use super::super::errno;

pub(super) fn handle_futex_lock_pi(uaddr: u64, timeout: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    // SAFETY: Reading current futex value
    let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };

    if current == 0 {
        // SAFETY: Acquiring uncontended lock
        unsafe {
            core::ptr::write_volatile(uaddr as *mut u32, pid);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    if (current & FUTEX_OWNER_DIED) != 0 {
        let new_val = pid | (current & FUTEX_WAITERS);
        // SAFETY: Taking over dead owner's lock
        unsafe {
            core::ptr::write_volatile(uaddr as *mut u32, new_val);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    let owner_tid = current & FUTEX_TID_MASK;
    if owner_tid == pid {
        return errno(35);
    }

    let with_waiters = current | FUTEX_WAITERS;
    // SAFETY: Setting waiters flag
    unsafe {
        core::ptr::write_volatile(uaddr as *mut u32, with_waiters);
    }

    handle_futex_wait(uaddr, with_waiters as u64, timeout, FUTEX_BITSET_MATCH_ANY, true)
}

pub(super) fn handle_futex_unlock_pi(uaddr: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    // SAFETY: Reading current futex value
    let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
    let owner_tid = current & FUTEX_TID_MASK;

    if owner_tid != pid {
        return errno(1);
    }

    if (current & FUTEX_WAITERS) != 0 {
        wake_futex(uaddr, 1, FUTEX_BITSET_MATCH_ANY);
    }

    // SAFETY: Releasing lock
    unsafe {
        core::ptr::write_volatile(uaddr as *mut u32, 0);
    }
    PI_OWNERS.lock().remove(&uaddr);

    ok(0)
}

pub(super) fn handle_futex_trylock_pi(uaddr: u64) -> SyscallResult {
    let pid = crate::process::current_pid().unwrap_or(0);

    // SAFETY: Reading current futex value
    let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };

    if current == 0 {
        // SAFETY: Acquiring uncontended lock
        unsafe {
            core::ptr::write_volatile(uaddr as *mut u32, pid);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    if (current & FUTEX_OWNER_DIED) != 0 {
        let new_val = pid | (current & FUTEX_WAITERS);
        // SAFETY: Taking over dead owner's lock
        unsafe {
            core::ptr::write_volatile(uaddr as *mut u32, new_val);
        }
        PI_OWNERS.lock().insert(uaddr, pid);
        return ok(0);
    }

    errno(11)
}

pub(super) fn handle_futex_wait_requeue_pi(uaddr: u64, val: u64, timeout: u64, uaddr2: u64, _val3: u64) -> SyscallResult {
    if uaddr2 == 0 || (uaddr2 & 3) != 0 {
        return errno(14);
    }

    // SAFETY: Reading current value
    let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
    if current != val as u32 {
        return errno(11);
    }

    handle_futex_wait(uaddr, val, timeout, FUTEX_BITSET_MATCH_ANY, true)
}

pub(super) fn handle_futex_cmp_requeue_pi(uaddr: u64, val: u64, val2: u64, uaddr2: u64, val3: u64) -> SyscallResult {
    if uaddr2 == 0 || (uaddr2 & 3) != 0 {
        return errno(14);
    }

    // SAFETY: Reading current value for comparison
    let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
    if current != val3 as u32 {
        return errno(11);
    }

    let max_wake = val as usize;
    let max_requeue = val2 as usize;

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

    if requeued > 0 {
        // SAFETY: Setting waiters flag on PI futex
        let current = unsafe { core::ptr::read_volatile(uaddr2 as *const u32) };
        if (current & FUTEX_WAITERS) == 0 && current != 0 {
            unsafe {
                core::ptr::write_volatile(uaddr2 as *mut u32, current | FUTEX_WAITERS);
            }
        }
    }

    FUTEX_WAKES.fetch_add(woken as u64, Ordering::Relaxed);
    ok(woken as i64)
}
