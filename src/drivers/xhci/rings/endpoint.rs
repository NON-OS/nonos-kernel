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

pub struct EndpointRing {
    ring: TransferRing,
    dci: u8,
    streaming: bool,
}

impl EndpointRing {
    pub fn new(entries: usize, dci: u8) -> XhciResult<Self> {
        let ring = TransferRing::new(entries)?;
        Ok(Self {
            ring,
            dci,
            streaming: false,
        })
    }

    pub fn enqueue(&mut self, trb: Trb) -> XhciResult<u64> {
        self.ring.enqueue(trb)
    }

    pub fn dequeue_ptr(&self) -> u64 {
        self.ring.dequeue_ptr()
    }

    pub fn base_phys(&self) -> u64 {
        self.ring.base_phys()
    }

    pub fn dci(&self) -> u8 {
        self.dci
    }

    pub fn cycle(&self) -> bool {
        self.ring.cycle
    }

    pub fn is_full(&self) -> bool {
        self.ring.is_full()
    }

    pub fn free_count(&self) -> usize {
        self.ring.free_count()
    }

    pub fn set_streaming(&mut self, enabled: bool) {
        self.streaming = enabled;
    }

    pub fn clear(&mut self) {
        self.ring.clear();
    }
}
