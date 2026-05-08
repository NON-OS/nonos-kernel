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

//! `MkPioWrite`. Write one byte / word / dword to a granted
//! port. The kernel is the only side that issues the
//! architectural `out` instruction.

use super::errno::errno_for;
use super::width;
use crate::process::current_pid;
use crate::syscall::microkernel::errnos::{ERRNO_INVAL, ERRNO_PERM};

pub fn sys_pio_write(grant_id: u64, port_offset: u64, w: u64, value: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    let off = match u16::try_from(port_offset) {
        Ok(v) => v,
        Err(_) => return ERRNO_INVAL,
    };
    let pw = match width::from_arg(w) {
        Some(pw) => pw,
        None => return ERRNO_INVAL,
    };
    let v = match u32::try_from(value) {
        Ok(v) => v,
        Err(_) => return ERRNO_INVAL,
    };
    match crate::hardware::broker::pio_write(pid, grant_id, off, pw, v) {
        Ok(()) => 0,
        Err(e) => errno_for(e),
    }
}
