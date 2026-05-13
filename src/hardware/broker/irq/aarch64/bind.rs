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

use crate::arch::aarch64::gic;
use crate::hardware::broker::claim;
use crate::hardware::broker::irq::types::{IrqBindError, IrqBindRequest, IrqBindResult};
use crate::hardware::broker::table;

use super::pending;
use super::trampoline;

// SPI range: 32..1019 inclusive. PPIs (16..31) and SGIs (0..15) are
// kernel-owned. 1020..1023 are special IAR values, never bound.
const SPI_MIN: u32 = 32;
const SPI_MAX: u32 = 1019;

pub fn bind(pid: u32, req: IrqBindRequest) -> Result<IrqBindResult, IrqBindError> {
    if req.flags != 0 {
        return Err(IrqBindError::UnsupportedFlags);
    }
    if req.vector_count != 0 {
        return Err(IrqBindError::BadVectorCount);
    }
    if req.irq_source < SPI_MIN || req.irq_source > SPI_MAX {
        return Err(IrqBindError::NotDeviceIrq);
    }

    let claim = claim::lookup(req.device_id).ok_or(IrqBindError::NotClaimed)?;
    if claim.pid != pid {
        return Err(IrqBindError::NotClaimed);
    }
    if claim.epoch != req.claim_epoch {
        return Err(IrqBindError::StaleEpoch);
    }

    // Match the request against the broker-published device IRQ. The
    // capsule does not get to invent intids; if the broker has not
    // surfaced an irq_source for this device, no bind is possible.
    let dev = table::list()
        .into_iter()
        .find(|r| r.device_id == req.device_id)
        .ok_or(IrqBindError::UnknownDevice)?;
    if dev.irq_source == 0 {
        return Err(IrqBindError::NotDeviceIrq);
    }
    if dev.irq_source != req.irq_source {
        return Err(IrqBindError::NotDeviceIrq);
    }

    let (_idx, grant_id) = pending::alloc(req.irq_source, pid, req.device_id, claim.epoch)
        .ok_or(IrqBindError::AlreadyBound)?;
    let Some(e) = pending::find_by_grant(grant_id) else {
        return Err(IrqBindError::PlatformError);
    };

    // Capsule-scoped claim on the GIC slot. Fails closed if a kernel
    // driver already owns the line; rolls back the pending slot.
    if gic::register_irq_handler_for_capsule(req.irq_source, trampoline::handle).is_err() {
        pending::free(e);
        return Err(IrqBindError::PlatformError);
    }
    gic::enable_irq(req.irq_source);

    Ok(IrqBindResult { grant_id, vector: 0 })
}
