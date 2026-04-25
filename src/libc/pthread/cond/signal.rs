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
use core::sync::atomic::Ordering;

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut PthreadCond) -> i32 {
    if cond.is_null() {
        return 22;
    }
    let c = &*cond;
    if c.waiters.load(Ordering::SeqCst) > 0 {
        c.seq.fetch_add(1, Ordering::Release);
        crate::syscall::sys_futex(&c.seq as *const _ as u64, 1, 1, 0, 0, 0);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut PthreadCond) -> i32 {
    if cond.is_null() {
        return 22;
    }
    let c = &*cond;
    let waiters = c.waiters.load(Ordering::SeqCst);
    if waiters > 0 {
        c.seq.fetch_add(1, Ordering::Release);
        crate::syscall::sys_futex(&c.seq as *const _ as u64, 1, waiters, 0, 0, 0);
    }
    0
}
