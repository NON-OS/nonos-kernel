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

use core::mem::size_of;

use crate::hardware::broker::IrqBindRequest;
use crate::process::current_pid;
use crate::syscall::microkernel::errnos::{ERRNO_FAULT, ERRNO_PERM};
use crate::usercopy::{validate_user_write, write_user_value};

use super::errno_map::bind_errno;
use super::out::IrqBindOut;

pub fn sys_irq_bind(
    device_id: u64,
    claim_epoch: u64,
    irq_source: u32,
    flags: u32,
    vector_count: u32,
    out_ptr: u64,
) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    if out_ptr == 0 {
        return ERRNO_FAULT;
    }
    if validate_user_write(out_ptr, size_of::<IrqBindOut>()).is_err() {
        return ERRNO_FAULT;
    }
    let req = IrqBindRequest { device_id, claim_epoch, irq_source, flags, vector_count };
    let r = match crate::hardware::broker::irq_bind(pid, req) {
        Ok(r) => r,
        Err(e) => return bind_errno(e),
    };
    let out = IrqBindOut { grant_id: r.grant_id, vector: r.vector as u64 };
    if write_user_value(out_ptr, &out).is_err() {
        // MSI-X bind allocated a run of N grants starting at r.grant_id.
        // Roll back the whole run for this pid+device. INTx collapses
        // to a single-grant release.
        let _ = crate::hardware::broker::irq_release_for_device(pid, device_id);
        return ERRNO_FAULT;
    }
    0
}
