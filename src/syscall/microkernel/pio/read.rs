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

//! `MkPioRead`. Read one byte / word / dword from a granted
//! port and write the result back as a `u32`.

use core::mem::size_of;

use super::errno::errno_for;
use super::width;
use crate::process::current_pid;
use crate::syscall::microkernel::errnos::{ERRNO_FAULT, ERRNO_INVAL, ERRNO_PERM};
use crate::usercopy::{validate_user_write, write_user_value};

pub fn sys_pio_read(grant_id: u64, port_offset: u64, w: u64, out_value: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    if out_value == 0 {
        return ERRNO_FAULT;
    }
    if validate_user_write(out_value, size_of::<u32>()).is_err() {
        return ERRNO_FAULT;
    }
    let off = match u16::try_from(port_offset) {
        Ok(v) => v,
        Err(_) => return ERRNO_INVAL,
    };
    let pw = match width::from_arg(w) {
        Some(pw) => pw,
        None => return ERRNO_INVAL,
    };
    let v = match crate::hardware::broker::pio_read(pid, grant_id, off, pw) {
        Ok(v) => v,
        Err(e) => return errno_for(e),
    };
    if write_user_value(out_value, &v).is_err() {
        return ERRNO_FAULT;
    }
    0
}
