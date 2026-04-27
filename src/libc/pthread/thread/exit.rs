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

use super::state::{CURRENT_THREAD, THREAD_TABLE};
use core::sync::atomic::Ordering;

/* DEV NOTES eK@nonos.systems
   Thread exit stores return value for pthread_join, marks thread inactive, and calls
   sys_exit. The kernel handles CLONE_CHILD_CLEARTID to signal waiters.
*/
#[no_mangle]
pub extern "C" fn pthread_exit(retval: *mut u8) -> ! {
    let tid = CURRENT_THREAD.load(Ordering::SeqCst);

    {
        let mut table = THREAD_TABLE.lock();
        for slot in table.iter_mut() {
            if let Some(ref mut tcb) = slot {
                if tcb.tid == tid {
                    tcb.retval.store(retval as u64, Ordering::Release);
                    tcb.active.store(0, Ordering::Release);
                    break;
                }
            }
        }
    }

    crate::syscall::sys_exit(0)
}
