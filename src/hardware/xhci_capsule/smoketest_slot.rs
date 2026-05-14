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

use super::client;
use super::error::DriverXhciError;

pub(super) fn prove_slot_lifecycle(max_slots: u8, baseline: u32) -> Result<(), SlotProofError> {
    let slot_id = client::enable_slot().map_err(SlotProofError::Client)?;
    if slot_id == 0 || slot_id > max_slots {
        return Err(SlotProofError::InvalidSlot);
    }
    let after_enable = client::controller_status().map_err(SlotProofError::Client)?;
    if after_enable.allocated_slots != baseline + 1 {
        return Err(SlotProofError::CountDidNotIncrease);
    }
    client::disable_slot(slot_id).map_err(SlotProofError::Client)?;
    let after_disable = client::controller_status().map_err(SlotProofError::Client)?;
    if after_disable.allocated_slots != baseline {
        return Err(SlotProofError::CountDidNotReturn);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SlotProofError {
    Client(DriverXhciError),
    InvalidSlot,
    CountDidNotIncrease,
    CountDidNotReturn,
}
