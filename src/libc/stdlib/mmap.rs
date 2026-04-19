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

use core::ffi::c_void;

pub const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

#[no_mangle]
pub unsafe extern "C" fn mmap(addr: *mut c_void, length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void {
    let result = crate::syscall::sys_mmap(addr as u64, length as u64, prot as u64, flags as u64, fd as u64, offset as u64);
    if (result as i64) < 0 { return MAP_FAILED; }
    result as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn munmap(addr: *mut c_void, length: usize) -> i32 {
    crate::syscall::sys_munmap(addr as u64, length as u64) as i32
}

#[no_mangle]
pub unsafe extern "C" fn brk(addr: *mut c_void) -> i32 {
    let result = crate::syscall::sys_brk(addr as u64);
    if result == addr as u64 { 0 } else { -1 }
}

#[no_mangle]
pub unsafe extern "C" fn sbrk(increment: isize) -> *mut c_void {
    let current = crate::syscall::sys_brk(0);
    if increment == 0 { return current as *mut c_void; }
    let new_brk = (current as isize + increment) as u64;
    let result = crate::syscall::sys_brk(new_brk);
    if result == new_brk { current as *mut c_void } else { MAP_FAILED }
}
