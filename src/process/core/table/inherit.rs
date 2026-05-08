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

//! Capability inheritance policy for new PCBs.
//!
//! `pcb.caps_bits` is read by the syscall contract and decoded
//! against `crate::capabilities::Capability`. This module is the
//! only producer of inherited bits and only ever returns values in
//! that namespace. Mixing the legacy `process::capabilities` enum
//! into a stored `caps_bits` would alias by accident — for example
//! its `UseCrypto` (bit 8) and the new `Debug` (bit 8) sit on the
//! same u64 column.

use core::sync::atomic::Ordering;

use super::super::types::Pid;
use super::types::PROCESS_TABLE;
use crate::capabilities::smoke::debug_grant;
use crate::capabilities::Capability;

pub(super) fn compute_inherited_caps(pid: Pid, parent_pid: Pid) -> u64 {
    if pid == 1 {
        return init_caps_bits();
    }
    match PROCESS_TABLE.find_by_pid(parent_pid) {
        Some(parent) => parent.caps_bits.load(Ordering::Acquire) & inheritable_bound(),
        None => 0,
    }
}

// Init's ambient set. Production builds keep `Debug` off; smoketest
// builds OR it back in via `debug_grant` so every later
// `exec_process` that inherits from init can mint `MkDebug`.
fn init_caps_bits() -> u64 {
    let mut bits = 0u64;
    for cap in Capability::all() {
        if matches!(cap, Capability::Debug) {
            continue;
        }
        bits |= cap.bit();
    }
    bits | debug_grant()
}

// Children inherit their parent's bits intersected with this bound.
// The bound is the full new-namespace surface today; a follow-up
// audit will narrow it once the production-ambient set is finalised.
fn inheritable_bound() -> u64 {
    let mut bits = 0u64;
    for cap in Capability::all() {
        bits |= cap.bit();
    }
    bits
}
