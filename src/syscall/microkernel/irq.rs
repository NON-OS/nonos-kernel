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

//! `MkIrq*` handlers. Cap-gated by `Capability::Irq` at the
//! contract layer. The handlers translate the syscall arguments
//! into broker IRQ operations and write the result back into the
//! caller's buffer for `MkIrqBind` / `MkIrqPoll`.

use core::mem::size_of;

use super::errnos::{
    ERRNO_BUSY, ERRNO_FAULT, ERRNO_INVAL, ERRNO_NODEV, ERRNO_NOMEM, ERRNO_NOTSUP, ERRNO_PERM,
    ERRNO_STALE,
};
use crate::hardware::broker::{IrqBindError, IrqBindRequest, IrqError};
use crate::process::current_pid;
use crate::usercopy::{validate_user_write, write_user_value};

#[repr(C)]
#[derive(Clone, Copy)]
struct IrqBindOut {
    grant_id: u64,
    vector: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IrqPollOut {
    seq: u64,
    overflow: u64,
}

const _: () = assert!(size_of::<IrqBindOut>() == 16);
const _: () = assert!(size_of::<IrqPollOut>() == 16);

pub fn sys_irq_bind(
    device_id: u64,
    claim_epoch: u64,
    irq_source: u32,
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
    if validate_user_write(out_ptr, size_of::<IrqBindOut>()).is_err() {
        return ERRNO_FAULT;
    }
    let req = IrqBindRequest { device_id, claim_epoch, irq_source, flags };
    let r = match crate::hardware::broker::irq_bind(pid, req) {
        Ok(r) => r,
        Err(e) => return bind_errno(e),
    };
    let out = IrqBindOut { grant_id: r.grant_id, vector: r.vector as u64 };
    if write_user_value(out_ptr, &out).is_err() {
        let _ = crate::hardware::broker::irq_unmap_grant(pid, r.grant_id);
        return ERRNO_FAULT;
    }
    0
}

pub fn sys_irq_unbind(grant_id: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    match crate::hardware::broker::irq_unmap_grant(pid, grant_id) {
        Ok(()) => 0,
        Err(IrqError::NotHolder) => ERRNO_PERM,
        Err(IrqError::UnknownGrant) => ERRNO_INVAL,
    }
}

pub fn sys_irq_ack(grant_id: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    match crate::hardware::broker::irq_ack_grant(pid, grant_id) {
        Ok(()) => 0,
        Err(IrqError::NotHolder) => ERRNO_PERM,
        Err(IrqError::UnknownGrant) => ERRNO_INVAL,
    }
}

pub fn sys_irq_poll(grant_id: u64, out_ptr: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    if out_ptr == 0 {
        return ERRNO_FAULT;
    }
    if validate_user_write(out_ptr, size_of::<IrqPollOut>()).is_err() {
        return ERRNO_FAULT;
    }
    let res = match crate::hardware::broker::irq_poll(pid, grant_id) {
        Ok(r) => r,
        Err(IrqError::NotHolder) => return ERRNO_PERM,
        Err(IrqError::UnknownGrant) => return ERRNO_INVAL,
    };
    let out = IrqPollOut { seq: res.seq, overflow: res.overflow };
    if write_user_value(out_ptr, &out).is_err() {
        return ERRNO_FAULT;
    }
    0
}

fn bind_errno(e: IrqBindError) -> i64 {
    match e {
        IrqBindError::NotClaimed => ERRNO_PERM,
        IrqBindError::StaleEpoch => ERRNO_STALE,
        IrqBindError::UnknownDevice => ERRNO_NODEV,
        IrqBindError::NotDeviceIrq | IrqBindError::NotIntx => ERRNO_INVAL,
        IrqBindError::AlreadyBound => ERRNO_BUSY,
        IrqBindError::NoVector => ERRNO_NOMEM,
        IrqBindError::UnsupportedFlags => ERRNO_NOTSUP,
        IrqBindError::PlatformError => ERRNO_NODEV,
    }
}
