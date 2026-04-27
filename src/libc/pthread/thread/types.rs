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

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64};

pub type PthreadT = u64;
pub type StartRoutine = extern "C" fn(*mut u8) -> *mut u8;

pub const PTHREAD_CREATE_JOINABLE: i32 = 0;
pub const PTHREAD_CREATE_DETACHED: i32 = 1;

#[repr(C)]
pub struct PthreadAttr {
    pub detachstate: i32,
    pub stacksize: usize,
    pub stack: *mut u8,
}

impl Default for PthreadAttr {
    fn default() -> Self {
        Self {
            detachstate: PTHREAD_CREATE_JOINABLE,
            stacksize: 8 * 1024 * 1024,
            stack: ptr::null_mut(),
        }
    }
}

/* DEV NOTES eK@nonos.systems
   Thread control block tracks each thread's state for join/detach. The tid_futex field
   is written to 0 by the kernel on thread exit (via CLONE_CHILD_CLEARTID) and used as
   the futex word for pthread_join to wait on.
*/
#[repr(C)]
pub struct ThreadControlBlock {
    pub tid: u64,
    pub pid: i32,
    pub tid_futex: AtomicU32,
    pub retval: AtomicU64,
    pub detached: AtomicU32,
    pub stack: *mut u8,
    pub stack_size: usize,
    pub active: AtomicU32,
}

unsafe impl Send for ThreadControlBlock {}
unsafe impl Sync for ThreadControlBlock {}
