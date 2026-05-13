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

use core::sync::atomic::Ordering;

use crate::arch::aarch64::gic;
use crate::hardware::broker::irq::types::IrqError;

use super::pending;

// Re-enable the SPI line that the trampoline masked. Owner check is
// the grant→pid match; non-owners hit `NotHolder`.
pub fn ack_grant(pid: u32, grant_id: u64) -> Result<(), IrqError> {
    let e = pending::find_by_grant(grant_id).ok_or(IrqError::UnknownGrant)?;
    if e.pid.load(Ordering::Acquire) != pid {
        return Err(IrqError::NotHolder);
    }
    let intid = e.intid.load(Ordering::Acquire);
    if intid == 0 {
        return Err(IrqError::UnknownGrant);
    }
    gic::enable_irq(intid);
    Ok(())
}
