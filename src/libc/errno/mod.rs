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

pub mod codes;

pub use codes::*;

#[thread_local]
static mut ERRNO_VALUE: i32 = 0;

#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut i32 {
    &raw mut ERRNO_VALUE
}

pub fn errno() -> i32 {
    unsafe { ERRNO_VALUE }
}

pub fn set_errno(val: i32) {
    unsafe {
        ERRNO_VALUE = val;
    }
}

pub type Errno = i32;
