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

#[no_mangle]
pub unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    let ts = crate::libc::time::Timespec { tv_sec: seconds as i64, tv_nsec: 0 };
    crate::libc::time::nanosleep(&ts, core::ptr::null_mut());
    0
}

#[no_mangle]
pub unsafe extern "C" fn usleep(usec: u32) -> i32 {
    let ts = crate::libc::time::Timespec { tv_sec: (usec / 1_000_000) as i64, tv_nsec: ((usec % 1_000_000) * 1000) as i64 };
    crate::libc::time::nanosleep(&ts, core::ptr::null_mut())
}
