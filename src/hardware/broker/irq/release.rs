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

//! Revocation paths: explicit `MkIrqUnbind`, exit teardown, and
//! `MkDeviceRelease`. Each path masks the IO-APIC line, deactivates
//! the slot so the dispatcher drops further deliveries, and frees
//! the vector back into the broker pool.

use super::types::{IrqError, IrqGrant};
use super::{records, slots};
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
    let _ = ioapic::mask(g.irq_source, false);
    Ok(())
}

pub fn release_for_device(pid: u32, device_id: u64) -> usize {
    let drained = records::drain_for_device(pid, device_id);
    for g in &drained {
        teardown(g);
    }
    drained.len()
}

pub fn release_all_for_pid(pid: u32) -> usize {
    let drained = records::drain_for_pid(pid);
    for g in &drained {
        teardown(g);
    }
    drained.len()
}

// The broker vector pool stays reserved in the IO-APIC's
// `VEC_ALLOC` for the life of the kernel; the broker's own slot
// bitmap is the source of truth for which broker vectors are in
// use. Releasing the vector to `VEC_ALLOC` here would surface it
// to non-broker callers and break the reservation invariant.
fn teardown(g: &IrqGrant) {
    let _ = ioapic::mask(g.irq_source, true);
    if let Some(idx) = slot_of(g.vector) {
        slots::deactivate(idx);
        slots::free_slot(idx);
    }
}
