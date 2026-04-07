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
pub unsafe extern "C" fn close(fd: i32) -> i32 { crate::syscall::sys_close(fd as u64) as i32 }

#[no_mangle]
pub unsafe extern "C" fn dup(oldfd: i32) -> i32 { crate::syscall::sys_dup(oldfd as usize) as i32 }

#[no_mangle]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 { crate::syscall::sys_dup2(oldfd as usize, newfd as usize) as i32 }

#[no_mangle]
pub unsafe extern "C" fn pipe(pipefd: *mut i32) -> i32 { crate::syscall::sys_pipe(pipefd as usize) as i32 }

#[no_mangle]
pub unsafe extern "C" fn lseek(fd: i32, offset: i64, whence: i32) -> i64 { crate::syscall::sys_lseek(fd as u64, offset as u64, whence as u64) }
