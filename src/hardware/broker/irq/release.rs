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

//! Revocation paths: explicit `MkIrqUnbind`, `MkIrqAck`, exit
//! teardown, and `MkDeviceRelease`. The unwind shape depends on
//! the grant kind:
//!
//!   * INTx — mask the IO-APIC line, deactivate the broker slot,
//!     free the slot back into the bitmap. The IO-APIC redirection
//!     entry is left programmed (idempotent and the line is
//!     masked); the next bind for the same GSI overwrites it.
//!   * MSI-X — mask the per-vector entry, zero the table entry so
//!     a stale message cannot be re-armed, deactivate and free the
//!     broker slot. When the unwind drops the last MSI-X grant
//!     for the device, the kernel issues a full disable so the
//!     device-side enable bit returns to its post-reset state.

use super::types::{IrqError, IrqGrant, IrqGrantKind};
use super::{bind as bind_internal, records, slots};
use crate::arch::interrupt::broker::slot_of;
use crate::arch::interrupt::ioapic;

pub fn unmap_grant(pid: u32, grant_id: u64) -> Result<(), IrqError> {
    let g = records::remove(pid, grant_id)?;
    teardown(&g);
    Ok(())
}

pub fn ack_grant(pid: u32, grant_id: u64) -> Result<(), IrqError> {
    let g = records::lookup(grant_id).ok_or(IrqError::UnknownGrant)?;
    if g.pid != pid {
        return Err(IrqError::NotHolder);
    }
    match g.kind {
        IrqGrantKind::Intx => {
            let _ = ioapic::mask(g.irq_source, false);
        }
        IrqGrantKind::Msix => {
            // MSI-X has no per-line IO-APIC mask. The dispatcher
            // leaves the per-vector mask alone, so an ack is a
            // no-op on the hardware side; capsules still call it
            // for symmetry with the INTx path.
        }
    }
    Ok(())
}

pub fn release_for_device(pid: u32, device_id: u64) -> usize {
    let drained = records::drain_for_device(pid, device_id);
    let count = drained.len();
    for g in &drained {
        teardown(g);
    }
    count
}

pub fn release_all_for_pid(pid: u32) -> usize {
    let drained = records::drain_for_pid(pid);
    let count = drained.len();
    for g in &drained {
        teardown(g);
    }
    count
}

// The broker vector pool stays reserved in the IO-APIC's
// `VEC_ALLOC` for the life of the kernel; the broker's own slot
// bitmap is the source of truth for which broker vectors are in
// use. Releasing the vector to `VEC_ALLOC` here would surface it
// to non-broker callers and break the reservation invariant.
fn teardown(g: &IrqGrant) {
    match g.kind {
        IrqGrantKind::Intx => teardown_intx(g),
        IrqGrantKind::Msix => teardown_msix(g),
    }
}

fn teardown_intx(g: &IrqGrant) {
    let _ = ioapic::mask(g.irq_source, true);
    if let Some(idx) = slot_of(g.vector) {
        slots::deactivate(idx);
        slots::free_slot(idx);
    }
}

fn teardown_msix(g: &IrqGrant) {
    bind_internal::teardown_msix_vector(g.device_id, g.device_vector);
    if let Some(idx) = slot_of(g.vector) {
        slots::deactivate(idx);
        slots::free_slot(idx);
    }
    if records::count_msix_for_device(g.device_id) == 0 {
        bind_internal::disable_msix_for_device(g.device_id);
    }
}
