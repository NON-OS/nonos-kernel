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

use super::constants::*;
use super::exit::pthread_exit;
use super::state::{CURRENT_THREAD, NEXT_TID, THREAD_TABLE};
use super::types::{PthreadAttr, PthreadT, StartRoutine, ThreadControlBlock};
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/* DEV NOTES eK@nonos.systems
   Thread creation using clone with CLONE_CHILD_CLEARTID. The kernel will write 0 to
   tid_futex on thread exit and wake any futex waiters, enabling proper pthread_join.
*/
#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut PthreadT,
    attr: *const PthreadAttr,
    start: StartRoutine,
    arg: *mut u8,
) -> i32 {
    if thread.is_null() {
        return 22;
    }

    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    let detached = if attr.is_null() { 0 } else { (*attr).detachstate as u32 };
    let stacksize = if attr.is_null() { 8 * 1024 * 1024 } else { (*attr).stacksize };

    let stack = crate::libc::stdlib::malloc::malloc(stacksize);
    if stack.is_null() {
        return 12;
    }

    let slot = {
        let mut table = THREAD_TABLE.lock();
        let slot = table.iter().position(|s| s.is_none());
        if let Some(idx) = slot {
            table[idx] = Some(ThreadControlBlock {
                tid,
                pid: 0,
                tid_futex: AtomicU32::new(1),
                retval: AtomicU64::new(0),
                detached: AtomicU32::new(detached),
                stack,
                stack_size: stacksize,
                active: AtomicU32::new(1),
            });
            idx
        } else {
            crate::libc::stdlib::free::free(stack);
            return 11;
        }
    };

    let clone_flags = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID;

    let child_stack = stack.add(stacksize - 16);

    let tid_ptr = {
        let table = THREAD_TABLE.lock();
        if let Some(ref tcb) = table[slot] {
            &tcb.tid_futex as *const AtomicU32 as usize
        } else {
            0
        }
    };

    let ret = crate::syscall::sys_clone(
        clone_flags,
        child_stack as u64,
        tid_ptr as u64,
        tid_ptr as u64,
        0,
    );

    if ret < 0 {
        let mut table = THREAD_TABLE.lock();
        table[slot] = None;
        crate::libc::stdlib::free::free(stack);
        return (-ret) as i32;
    }

    if ret == 0 {
        CURRENT_THREAD.store(tid, Ordering::SeqCst);
        let result = start(arg);
        pthread_exit(result);
    }

    {
        let mut table = THREAD_TABLE.lock();
        if let Some(ref mut tcb) = table[slot] {
            tcb.pid = ret as i32;
        }
    }

    ptr::write(thread, tid);
    0
}
