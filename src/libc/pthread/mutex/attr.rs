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

use super::types::{PthreadMutexattr, PTHREAD_MUTEX_NORMAL};
use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut PthreadMutexattr) -> i32 {
    if attr.is_null() {
        return 22;
    }
    ptr::write(attr, PthreadMutexattr { kind: PTHREAD_MUTEX_NORMAL });
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_settype(attr: *mut PthreadMutexattr, kind: i32) -> i32 {
    if attr.is_null() {
        return 22;
    }
    (*attr).kind = kind;
    0
}
