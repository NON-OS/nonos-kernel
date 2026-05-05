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

//! Microkernel device-broker syscalls.
//!
//! Three calls are wired today: enumerate the device table, claim a
//! device for the calling pid, and release a held claim. Each call
//! consults the broker's per-pid claim table; the kernel's `MkExit`
//! path walks that table to revoke any grants the dying pid still
//! held.
//!
//! Cap-gated at the contract layer by `Capability::DeviceEnum`. The
//! handlers never re-check the capability themselves; reaching here
//! already proves it.

use core::mem::size_of;

use crate::hardware::broker::{self, ClaimError, DeviceRecord};
use crate::process::current_pid;
use crate::usercopy::{validate_user_write, write_user_value};

// Errno values returned to userland. Sign is preserved.
const ERRNO_PERM: i64 = -1;
const ERRNO_INVAL: i64 = -22;
const ERRNO_FAULT: i64 = -14;
const ERRNO_NODEV: i64 = -19;
const ERRNO_BUSY: i64 = -16;

/// Returns a snapshot of the broker's device table filtered by class.
///
/// `count == 0` is the probe form: returns the table size for the
/// class, no user-buffer access. Otherwise writes up to `count`
/// records to `buf_ptr` and returns the number written.
///
/// `class == 0` returns every device.
pub fn sys_device_list(class: u32, buf_ptr: u64, count: u64) -> i64 {
    let snapshot = broker::list_by_class(class);
    let total = snapshot.len();
    if count == 0 {
        return total as i64;
    }
    if buf_ptr == 0 {
        return ERRNO_FAULT;
    }
    let to_write = core::cmp::min(count as usize, total);
    let bytes = match (to_write as u64).checked_mul(size_of::<DeviceRecord>() as u64) {
        Some(v) => v,
        None => return ERRNO_INVAL,
    };
    if validate_user_write(buf_ptr, bytes as usize).is_err() {
        return ERRNO_FAULT;
    }
    let stride = size_of::<DeviceRecord>() as u64;
    for (i, rec) in snapshot.iter().take(to_write).enumerate() {
        let dst = buf_ptr + (i as u64) * stride;
        if write_user_value(dst, rec).is_err() {
            return ERRNO_FAULT;
        }
    }
    to_write as i64
}

/// Claims `device_id` for the calling pid.
///
/// The caller becomes the device's exclusive holder. Subsequent
/// MMIO/IRQ/DMA grants for the device are checked against this
/// claim. Returns the granted epoch on success; the same epoch is
/// stamped onto every grant the holder requests, so a revoked
/// grant fails fast with `ESTALE` even if the device is later
/// re-claimed by someone else.
pub fn sys_device_claim(device_id: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    if !broker::contains(device_id) {
        return ERRNO_NODEV;
    }
    match broker::claim_device(pid, device_id) {
        Ok(epoch) => epoch as i64,
        Err(ClaimError::AlreadyClaimed) => ERRNO_BUSY,
        Err(ClaimError::UnknownDevice) => ERRNO_NODEV,
        Err(ClaimError::NotHolder) | Err(ClaimError::NotClaimed) => ERRNO_INVAL,
    }
}

/// Releases the calling pid's claim on `device_id`.
///
/// Only the holder pid can release. The kernel exit path performs
/// the equivalent of this for every held device when the holder pid
/// dies; userland calls this when it is shutting down a driver
/// gracefully.
pub fn sys_device_release(device_id: u64) -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    match broker::release_device(pid, device_id) {
        Ok(_epoch) => 0,
        Err(ClaimError::NotClaimed) => ERRNO_NODEV,
        Err(ClaimError::NotHolder) => ERRNO_PERM,
        Err(ClaimError::AlreadyClaimed) | Err(ClaimError::UnknownDevice) => ERRNO_INVAL,
    }
}
