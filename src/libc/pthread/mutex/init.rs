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

use super::types::{PthreadMutex, PthreadMutexattr, PTHREAD_MUTEX_NORMAL};
use core::ptr;
use core::sync::atomic::AtomicU32;

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut PthreadMutex,
    attr: *const PthreadMutexattr,
) -> i32 {
    if mutex.is_null() {
        return 22;
    }
    let kind = if attr.is_null() { PTHREAD_MUTEX_NORMAL } else { (*attr).kind };
    ptr::write(mutex, PthreadMutex { lock: AtomicU32::new(0), kind, owner: 0, count: 0 });
    0
}
