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

//! MkMmioMap / MkMmioUnmap syscall handlers.
//!
//! Cap-gated by `Capability::Mmio` at the contract layer. The
//! handlers translate userland's syscall arguments into a broker
//! `MmioMapRequest`, write the result back into the caller's buffer,
//! and roll the grant back if that copy fails. They are the only
//! path that carries a physical-mapping request into the kernel —
//! the static checks enforce it.

use core::mem::size_of;

use super::errnos::{
    ERRNO_FAULT, ERRNO_INVAL, ERRNO_NODEV, ERRNO_NOMEM, ERRNO_NOTSUP, ERRNO_PERM, ERRNO_STALE,
};
use crate::hardware::broker::{self, GrantError, MmioMapError, MmioMapRequest};
use crate::process::current_pid;
use crate::usercopy::{validate_user_write, write_user_value};

#[repr(C)]
#[derive(Clone, Copy)]
struct MmioMapOut {
    user_va: u64,
    length: u64,
    grant_id: u64,
}

const _: () = assert!(size_of::<MmioMapOut>() == 24);

pub fn sys_mmio_map(
    device_id: u64,
    claim_epoch: u64,
    bar_index: u32,
    offset: u64,
    length: u64,
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
    if validate_user_write(out_ptr, size_of::<MmioMapOut>()).is_err() {
        return ERRNO_FAULT;
    }
    if bar_index > u8::MAX as u32 {
        return ERRNO_INVAL;
    }
    let req = MmioMapRequest {
        device_id,
        claim_epoch,
        bar_index: bar_index as u8,
        offset,
        length,
        flags,
    };
    let result = match broker::map_for_caller(pid, req) {
        Ok(r) => r,
        Err(e) => return errno_for(e),
    };
    let out =
        MmioMapOut { user_va: result.user_va, length: result.length, grant_id: result.grant_id };
    if write_user_value(out_ptr, &out).is_err() {
        // The pages are mapped but the caller cannot see the result.
        // Roll the grant back so we do not leak a window with no
        // userland handle.
        let _ = broker::unmap_grant(pid, result.grant_id);
        return ERRNO_FAULT;
    }
    0
}

pub fn sys_mmio_unmap(grant_id: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    match broker::unmap_grant(pid, grant_id) {
        Ok(()) => 0,
        Err(GrantError::NotHolder) => ERRNO_PERM,
        Err(GrantError::UnknownGrant) => ERRNO_INVAL,
    }
}

fn errno_for(e: MmioMapError) -> i64 {
    match e {
        MmioMapError::NotClaimed => ERRNO_PERM,
        MmioMapError::StaleEpoch => ERRNO_STALE,
        MmioMapError::UnknownDevice => ERRNO_NODEV,
        MmioMapError::BadBarIndex
        | MmioMapError::NotMmioBar
        | MmioMapError::BadAlignment
        | MmioMapError::BadRange
        | MmioMapError::ZeroLength
        | MmioMapError::Overflow => ERRNO_INVAL,
        MmioMapError::WouldExposeMsixTable | MmioMapError::WouldExposePba => ERRNO_PERM,
        MmioMapError::UnsupportedFlags => ERRNO_NOTSUP,
        MmioMapError::NoVaSpace | MmioMapError::MapFailed => ERRNO_NOMEM,
    }
}
