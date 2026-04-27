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

use super::constants::FUTEX_WAIT;
use super::state::THREAD_TABLE;
use super::types::PthreadT;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/* DEV NOTES eK@nonos.systems
   Wait for thread completion using futex. The kernel sets tid_futex to 0 on thread exit
   (via CLONE_CHILD_CLEARTID) and wakes waiters. We loop until tid_futex becomes 0,
   then retrieve return value and clean up thread resources.
*/
#[no_mangle]
pub unsafe extern "C" fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32 {
    let slot = {
        let table = THREAD_TABLE.lock();
        table.iter().position(|s| s.as_ref().map(|t| t.tid == thread).unwrap_or(false))
    };

    let slot = match slot {
        Some(s) => s,
        None => return 3,
    };

    {
        let table = THREAD_TABLE.lock();
        if let Some(ref tcb) = table[slot] {
            if tcb.detached.load(Ordering::SeqCst) != 0 {
                return 22;
            }
        }
    }

    loop {
        let (futex_ptr, futex_val) = {
            let table = THREAD_TABLE.lock();
            if let Some(ref tcb) = table[slot] {
                let val = tcb.tid_futex.load(Ordering::Acquire);
                if val == 0 {
                    break;
                }
                (&tcb.tid_futex as *const AtomicU32 as usize, val)
            } else {
                break;
            }
        };

        crate::syscall::sys_futex(futex_ptr as u64, FUTEX_WAIT, futex_val, 0, 0, 0);
    }

    let (ret_ptr, stack) = {
        let mut table = THREAD_TABLE.lock();
        if let Some(tcb) = table[slot].take() {
            let rv = tcb.retval.load(Ordering::Acquire) as *mut u8;
            (rv, tcb.stack)
        } else {
            (ptr::null_mut(), ptr::null_mut())
        }
    };

    if !retval.is_null() {
        ptr::write(retval, ret_ptr);
    }

    if !stack.is_null() {
        crate::libc::stdlib::free::free(stack);
    }

    0
}
