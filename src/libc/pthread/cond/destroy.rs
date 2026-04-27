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
use core::ptr;
use core::sync::atomic::Ordering;

/* DEV NOTES eK@nonos.systems
   Destroy condition variable. Returns EBUSY if threads are waiting, EINVAL if null.
   Zeroizes the structure to catch use-after-destroy bugs.
*/
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut PthreadCond) -> i32 {
    if cond.is_null() {
        return 22;
    }
    let c = &*cond;
    if c.waiters.load(Ordering::Acquire) > 0 {
        return 16;
    }
    ptr::write_bytes(cond, 0, 1);
    0
}
