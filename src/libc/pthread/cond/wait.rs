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

use super::types::PthreadCond;
use crate::libc::pthread::mutex::PthreadMutex;
use core::sync::atomic::Ordering;

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_wait(
    cond: *mut PthreadCond,
    mutex: *mut PthreadMutex,
) -> i32 {
    if cond.is_null() || mutex.is_null() {
        return 22;
    }
    let c = &*cond;
    let seq = c.seq.load(Ordering::Acquire);
    c.waiters.fetch_add(1, Ordering::SeqCst);
    crate::libc::pthread::mutex::pthread_mutex_unlock(mutex);
    crate::syscall::sys_futex(&c.seq as *const _ as u64, 0, seq, 0, 0, 0);
    c.waiters.fetch_sub(1, Ordering::SeqCst);
    crate::libc::pthread::mutex::pthread_mutex_lock(mutex);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut PthreadCond,
    mutex: *mut PthreadMutex,
    abstime: *const crate::libc::time::Timespec,
) -> i32 {
    if cond.is_null() || mutex.is_null() {
        return 22;
    }
    let c = &*cond;
    let seq = c.seq.load(Ordering::Acquire);
    c.waiters.fetch_add(1, Ordering::SeqCst);
    crate::libc::pthread::mutex::pthread_mutex_unlock(mutex);
    let timeout = if abstime.is_null() {
        0
    } else {
        ((*abstime).tv_sec * 1_000_000_000 + (*abstime).tv_nsec) as u64
    };
    let ret = crate::syscall::sys_futex(&c.seq as *const _ as u64, 0, seq, timeout, 0, 0);
    c.waiters.fetch_sub(1, Ordering::SeqCst);
    crate::libc::pthread::mutex::pthread_mutex_lock(mutex);
    if ret == -110 {
        110
    } else {
        0
    }
}
