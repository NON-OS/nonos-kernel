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

use super::helpers::wake_futex;
use super::types::{ok, FutexWaiter, FUTEX_WAITER_MAP, FUTEX_WAITS, FUTEX_TIMEOUTS};
use crate::syscall::SyscallResult;
use super::super::errno;

pub(super) fn handle_futex_wait(uaddr: u64, val: u64, timeout: u64, bitset: u32, is_pi: bool) -> SyscallResult {
    if bitset == 0 {
        return errno(22);
    }

    // SAFETY: Reading current futex value
    let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
    if current != val as u32 {
        return errno(11);
    }

    let deadline = if timeout != 0 {
        // SAFETY: Reading timeout structure from user
        let ts_sec = unsafe { core::ptr::read(timeout as *const i64) };
        let ts_nsec = unsafe { core::ptr::read((timeout + 8) as *const i64) };
        if ts_sec < 0 || ts_nsec < 0 || ts_nsec >= 1_000_000_000 {
            return errno(22);
        }
        let now = crate::time::timestamp_millis();
        now.saturating_add((ts_sec as u64) * 1000).saturating_add((ts_nsec as u64) / 1_000_000)
    } else {
        u64::MAX
    };

    let pid = crate::process::current_pid().unwrap_or(0);
    FUTEX_WAITS.fetch_add(1, Ordering::Relaxed);

    FUTEX_WAITER_MAP.lock().entry(uaddr).or_insert_with(Vec::new).push(FutexWaiter {
        pid,
        bitset,
        is_pi,
    });

    loop {
        let still_waiting = FUTEX_WAITER_MAP.lock()
            .get(&uaddr)
            .map(|v| v.iter().any(|w| w.pid == pid))
            .unwrap_or(false);

        if !still_waiting {
            return ok(0);
        }

        if crate::time::timestamp_millis() >= deadline {
            if let Some(waiters) = FUTEX_WAITER_MAP.lock().get_mut(&uaddr) {
                waiters.retain(|w| w.pid != pid);
            }
            FUTEX_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            return errno(110);
        }

        // SAFETY: Re-checking futex value
        let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
        if current != val as u32 {
            if let Some(waiters) = FUTEX_WAITER_MAP.lock().get_mut(&uaddr) {
                waiters.retain(|w| w.pid != pid);
            }
            return errno(11);
        }

        crate::sched::yield_cpu();
    }
}

pub(super) fn handle_futex_wake(uaddr: u64, val: u64, bitset: u32) -> SyscallResult {
    if bitset == 0 {
        return errno(22);
    }

    let woken = wake_futex(uaddr, val as usize, bitset);
    ok(woken as i64)
}
