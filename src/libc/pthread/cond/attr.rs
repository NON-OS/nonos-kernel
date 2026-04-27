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

use super::types::PthreadCondattr;
use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_init(attr: *mut PthreadCondattr) -> i32 {
    if attr.is_null() {
        return 22;
    }
    ptr::write(attr, PthreadCondattr { clock: 0 });
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_setclock(attr: *mut PthreadCondattr, clock: i32) -> i32 {
    if attr.is_null() {
        return 22;
    }
    (*attr).clock = clock;
    0
}
