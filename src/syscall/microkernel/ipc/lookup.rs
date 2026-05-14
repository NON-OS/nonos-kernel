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

extern crate alloc;

use alloc::vec;

use crate::services::registry::lookup_service;
use crate::syscall::microkernel::errnos::{ERRNO_FAULT, ERRNO_INVAL, ERRNO_NOENT};

const NAME_MAX: usize = 64;

// `MkServiceLookup(name_ptr, name_len, *port_out, *pid_out)`. The
// caller passes the service name they want to resolve; the kernel
// reads it (bounded by `NAME_MAX`), consults the service registry,
// and writes the port and owning pid into the two output u32s.
// Returns 0 on success or a negative errno. Capsule clients use
// this in setup so they do not have to hardcode peer ports.
pub fn sys_service_lookup(
    name_ptr: u64,
    name_len: usize,
    port_out: u64,
    pid_out: u64,
) -> i64 {
    if name_len == 0 || name_len > NAME_MAX {
        return ERRNO_INVAL;
    }
    if crate::usercopy::validate_user_read(name_ptr, name_len).is_err() {
        return ERRNO_FAULT;
    }
    let u32_size = core::mem::size_of::<u32>();
    if port_out != 0 && crate::usercopy::validate_user_write(port_out, u32_size).is_err() {
        return ERRNO_FAULT;
    }
    if pid_out != 0 && crate::usercopy::validate_user_write(pid_out, u32_size).is_err() {
        return ERRNO_FAULT;
    }
    let mut name_buf = vec![0u8; name_len];
    if crate::usercopy::copy_from_user(name_ptr, &mut name_buf).is_err() {
        return ERRNO_FAULT;
    }
    let name = match core::str::from_utf8(&name_buf) {
        Ok(s) => s,
        Err(_) => return ERRNO_INVAL,
    };
    let ep = match lookup_service(name) {
        Some(e) => e,
        None => return ERRNO_NOENT,
    };
    if port_out != 0 {
        let bytes = ep.port.to_le_bytes();
        if crate::usercopy::copy_to_user(port_out, &bytes).is_err() {
            return ERRNO_FAULT;
        }
    }
    if pid_out != 0 {
        let bytes = ep.pid.to_le_bytes();
        if crate::usercopy::copy_to_user(pid_out, &bytes).is_err() {
            return ERRNO_FAULT;
        }
    }
    0
}
