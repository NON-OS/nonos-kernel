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

//! `MkPioGrant`. Translate the syscall arguments into a broker
//! PIO grant request, write the result back into the caller's
//! buffer, and roll the grant back if that copy fails.

use core::mem::size_of;

use super::errno::errno_for;
use crate::hardware::broker::PioGrantRequest;
use crate::process::current_pid;
use crate::syscall::microkernel::errnos::{ERRNO_FAULT, ERRNO_PERM};
use crate::usercopy::{validate_user_write, write_user_value};

#[repr(C)]
#[derive(Clone, Copy)]
struct PioGrantOut {
    port_base: u16,
    port_count: u16,
    _pad: u32,
    grant_id: u64,
}

const _: () = assert!(size_of::<PioGrantOut>() == 16);

pub fn sys_pio_grant(
    device_id: u64,
    claim_epoch: u64,
    bar_index: u8,
    flags: u32,
    out_ptr: u64,
) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    if out_ptr == 0 {
        return ERRNO_FAULT;
    }
    if validate_user_write(out_ptr, size_of::<PioGrantOut>()).is_err() {
        return ERRNO_FAULT;
    }
    let req = PioGrantRequest { device_id, claim_epoch, bar_index, flags };
    let r = match crate::hardware::broker::pio_grant_for_caller(pid, req) {
        Ok(r) => r,
        Err(e) => return errno_for(e),
    };
    let out = PioGrantOut {
        port_base: r.port_base,
        port_count: r.port_count,
        _pad: 0,
        grant_id: r.grant_id,
    };
    if write_user_value(out_ptr, &out).is_err() {
        let _ = crate::hardware::broker::pio_release_grant(pid, r.grant_id);
        return ERRNO_FAULT;
    }
    0
}
