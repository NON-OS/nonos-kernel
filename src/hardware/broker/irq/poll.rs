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

//! Non-blocking polling primitive for `MkIrqPoll`. The capsule
//! reads the per-grant event counter; the syscall handler maps
//! that into a (seq, overflow) pair the holder can compare with
//! its last observation.

use super::records;
use super::slots;
use super::types::{IrqError, IrqPollResult};
use crate::arch::interrupt::broker::slot_of;

pub fn poll(pid: u32, grant_id: u64) -> Result<IrqPollResult, IrqError> {
    let g = records::lookup(grant_id).ok_or(IrqError::UnknownGrant)?;
    if g.pid != pid {
        return Err(IrqError::NotHolder);
    }
    let slot_idx = slot_of(g.vector).ok_or(IrqError::UnknownGrant)?;
    let (seq, overflow) = slots::read_counters(slot_idx);
    Ok(IrqPollResult { seq, overflow })
}
