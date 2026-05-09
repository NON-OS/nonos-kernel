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

//! `MkCap*` syscall handlers. Mutate `pcb.caps_bits` through
//! `process::caps`; there is no separate per-pid capability table.
//! The contract layer has already verified the caller token; this
//! layer enforces the additional caller-must-hold-Admin policy and
//! the subset rule.

use super::super::errnos::ERRNO_PERM;
use crate::capabilities::Capability;
use crate::process::caps;
use crate::process::current_pid;

#[inline]
fn admin_bit() -> u64 {
    Capability::Admin.bit()
}

pub fn sys_cap_grant(target_pid: u32, caps_mask: u64) -> i64 {
    let caller = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    let held = match caps::bits(caller) {
        Some(b) => b,
        None => return ERRNO_PERM,
    };
    // Caller must (1) hold Admin and (2) hold every bit it tries to
    // grant. The subset check stops an admin from manufacturing
    // authority it does not itself possess.
    if held & admin_bit() == 0 || held & caps_mask != caps_mask {
        return ERRNO_PERM;
    }
    if caps::grant(target_pid, caps_mask).is_none() {
        return ERRNO_PERM;
    }
    0
}

pub fn sys_cap_revoke(target_pid: u32, caps_mask: u64) -> i64 {
    let caller = match current_pid() {
        Some(p) => p,
        None => return ERRNO_PERM,
    };
    if !caps::has(caller, admin_bit()) {
        return ERRNO_PERM;
    }
    if caps::revoke(target_pid, caps_mask).is_none() {
        return ERRNO_PERM;
    }
    0
}

pub fn sys_cap_check(target_pid: u32, caps_mask: u64) -> i64 {
    if caps::has(target_pid, caps_mask) { 1 } else { 0 }
}
