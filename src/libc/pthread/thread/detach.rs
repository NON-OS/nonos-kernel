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

use super::state::THREAD_TABLE;
use super::types::PthreadT;
use core::sync::atomic::Ordering;

/* DEV NOTES eK@nonos.systems
   Mark thread as detached. Detached threads cannot be joined and their resources are
   automatically freed on exit. Returns EINVAL if thread already joined or not found.
*/
#[no_mangle]
pub unsafe extern "C" fn pthread_detach(thread: PthreadT) -> i32 {
    let mut table = THREAD_TABLE.lock();
    for slot in table.iter_mut() {
        if let Some(ref mut tcb) = slot {
            if tcb.tid == thread {
                if tcb.detached.swap(1, Ordering::SeqCst) != 0 {
                    return 22;
                }
                if tcb.active.load(Ordering::Acquire) == 0 {
                    let stack = tcb.stack;
                    *slot = None;
                    if !stack.is_null() {
                        crate::libc::stdlib::free::free(stack);
                    }
                }
                return 0;
            }
        }
    }
    3
}
