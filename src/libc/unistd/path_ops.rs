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
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 { crate::syscall::sys_chdir(path as usize) as i32 }

#[no_mangle]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    let ret = crate::syscall::sys_getcwd(buf as usize, size);
    if ret < 0 { core::ptr::null_mut() } else { buf }
}

#[no_mangle]
pub unsafe extern "C" fn unlink(path: *const u8) -> i32 { crate::syscall::sys_unlink(path as u64) as i32 }

#[no_mangle]
pub unsafe extern "C" fn rmdir(path: *const u8) -> i32 { crate::syscall::sys_rmdir(path as u64) as i32 }

#[no_mangle]
pub unsafe extern "C" fn access(path: *const u8, mode: i32) -> i32 { crate::syscall::sys_access(path as usize, mode) as i32 }
