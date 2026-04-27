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

use super::types::{PthreadCond, PthreadCondattr};
use core::ptr;
use core::sync::atomic::AtomicU32;

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_init(
    cond: *mut PthreadCond,
    _attr: *const PthreadCondattr,
) -> i32 {
    if cond.is_null() {
        return 22;
    }
    ptr::write(cond, PthreadCond { seq: AtomicU32::new(0), waiters: AtomicU32::new(0) });
    0
}
