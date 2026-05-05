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

//! `MkIrqBind` core: validate ownership, allocate a vector slot,
//! program the IO-APIC redirection. The path runs in syscall
//! context. The line is left masked; the holder unmasks via
//! `MkIrqAck` once it has wired its handler.

use super::records;
use super::slots;
use super::types::{IrqBindError, IrqBindRequest, IrqBindResult, IrqGrant};
use crate::arch::interrupt::broker::vector_of;
use crate::arch::interrupt::ioapic;
use crate::hardware::broker::{claim, table};

const FLAGS_KNOWN: u32 = 0;

pub fn bind(pid: u32, req: IrqBindRequest) -> Result<IrqBindResult, IrqBindError> {
    if req.flags & !FLAGS_KNOWN != 0 {
        return Err(IrqBindError::UnsupportedFlags);
    }
    let claim = claim::lookup(req.device_id).ok_or(IrqBindError::NotClaimed)?;
    if claim.pid != pid {
        return Err(IrqBindError::NotClaimed);
    }
    if claim.epoch != req.claim_epoch {
        return Err(IrqBindError::StaleEpoch);
    }
    let device = table::list()
        .into_iter()
        .find(|r| r.device_id == req.device_id)
        .ok_or(IrqBindError::UnknownDevice)?;
    // Legacy INTx only: `irq_source` must equal the device's PCI
    // interrupt_line as reported by the broker enumeration. MSI /
    // MSI-X is deferred until the broker grows MSI vector
    // allocation.
    if device.irq_pin == 0 || device.irq_line == 0xFF {
        return Err(IrqBindError::NotIntx);
    }
    if req.irq_source != device.irq_line as u32 {
        return Err(IrqBindError::NotDeviceIrq);
    }
    if records::vector_for_gsi(req.irq_source).is_some() {
        return Err(IrqBindError::AlreadyBound);
    }

    let slot = slots::try_alloc_slot().ok_or(IrqBindError::NoVector)?;
    let vector = vector_of(slot).ok_or(IrqBindError::NoVector)?;
    let dest_apic_id = crate::arch::interrupt::apic::id();

    if ioapic::program_route_external(req.irq_source, vector, dest_apic_id).is_err() {
        slots::free_slot(slot);
        return Err(IrqBindError::PlatformError);
    }
    let _ = ioapic::mask(req.irq_source, true);

    let grant_id = records::allocate_id();
    records::insert(IrqGrant {
        grant_id,
        pid,
        device_id: req.device_id,
        claim_epoch: claim.epoch,
        irq_source: req.irq_source,
        vector,
        flags: req.flags,
    });
    slots::activate(slot, grant_id, req.irq_source);

    Ok(IrqBindResult { grant_id, vector })
}
