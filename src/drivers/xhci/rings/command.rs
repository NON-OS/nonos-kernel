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

use super::super::error::XhciResult;
use super::super::trb::Trb;
use super::transfer::TransferRing;

pub struct CommandRing {
    ring: TransferRing,
}

impl CommandRing {
    pub fn new(entries: usize) -> XhciResult<Self> {
        let ring = TransferRing::new(entries)?;
        Ok(Self { ring })
    }

    pub fn enqueue(&mut self, trb: Trb) -> XhciResult<u64> {
        trb.validate_command_type()?;

        // SAFETY: command type already validated
        unsafe { self.ring.enqueue_raw(trb) }
    }

    pub fn crcr_value(&self) -> u64 {
        (self.ring.base_phys() & !0x3F) | (self.ring.cycle as u64)
    }

    pub fn cycle(&self) -> bool {
        self.ring.cycle
    }

    pub fn clear(&mut self) {
        self.ring.clear();
    }
}
