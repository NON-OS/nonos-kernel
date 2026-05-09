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

//! Per-pid capability mask operations against `pcb.caps_bits`.
//!
//! `caps_bits` is the single source of truth for what a process is
//! allowed to do. The syscall contract (`Capability::resolve`) reads
//! it through `proc.capability_token()`, IPC routing reads it through
//! `has`, and `MkCap*` mutates it through `grant` / `revoke`. There
//! is no parallel per-pid table.
//!
//! Bit values come from `crate::capabilities::Capability::bit()`.
//! Callers must use that enum; raw u64 literals are not part of the
//! contract.

use core::sync::atomic::Ordering;

use super::api::{with_process, with_process_mut};

/// Read the calling-or-target process's full capability mask. Returns
/// `None` if the pid is not in the process table.
pub fn bits(pid: u32) -> Option<u64> {
    with_process(pid, |pcb| pcb.caps_bits.load(Ordering::Acquire))
}

/// Test whether `pid` holds every bit in `mask`. Returns `false` for
/// an unknown pid (fail-closed).
pub fn has(pid: u32, mask: u64) -> bool {
    bits(pid).map(|b| (b & mask) == mask).unwrap_or(false)
}

/// Set every bit of `mask` on `pid`'s capability set. Returns `None`
/// if the pid is not in the table; the caller is responsible for any
/// authority check (`has(caller, Capability::Admin.bit())` etc.) before
/// reaching here.
pub fn grant(pid: u32, mask: u64) -> Option<()> {
    with_process_mut(pid, |pcb| {
        pcb.caps_bits.fetch_or(mask, Ordering::SeqCst);
    })
}

/// Clear every bit of `mask` on `pid`'s capability set. Same authority
/// contract as `grant`.
pub fn revoke(pid: u32, mask: u64) -> Option<()> {
    with_process_mut(pid, |pcb| {
        pcb.caps_bits.fetch_and(!mask, Ordering::SeqCst);
    })
}
