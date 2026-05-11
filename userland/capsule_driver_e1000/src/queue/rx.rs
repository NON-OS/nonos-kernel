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

//! RX ring state. The capsule pre-fills every descriptor with a
//! buffer phys-addr at bring-up; the device sets `status.DD` when
//! a frame lands. `consume` returns the oldest unread frame (or
//! `None` when the ring is empty) and clears the descriptor's
//! status so the slot can be re-armed before RDT advances.

use crate::constants::queue::{RX_BUFFER_LEN, RX_DESC_COUNT, RX_STATUS_DD};

use super::layout::RxDesc;

pub struct RxRing {
    pub ring_user_va: u64,
    pub buffer_user_va: u64,
    pub buffer_device_addr: u64,
    pub head: u16,
}

impl RxRing {
    pub fn new(ring_user_va: u64, buffer_user_va: u64, buffer_device_addr: u64) -> Self {
        Self { ring_user_va, buffer_user_va, buffer_device_addr, head: 0 }
    }

    /// # Safety
    /// `ring_user_va` must point to RX_DESC_COUNT contiguous
    /// `RxDesc`s mapped read+write into this address space.
    pub unsafe fn descriptor(&self, idx: u16) -> *mut RxDesc {
        let base = self.ring_user_va as *mut RxDesc;
        base.add(idx as usize)
    }

    pub fn buffer_phys(&self, idx: u16) -> u64 {
        self.buffer_device_addr + (idx as u64) * (RX_BUFFER_LEN as u64)
    }

    pub fn buffer_va(&self, idx: u16) -> u64 {
        self.buffer_user_va + (idx as u64) * (RX_BUFFER_LEN as u64)
    }

    /// Return the next descriptor with `DD` set, or `None`.
    pub fn consume(&mut self) -> Option<(u16, u16)> {
        // SAFETY: eK@nonos.systems — `ring_user_va` is the broker
        // DMA grant we asked for in `setup::dma`; descriptor index
        // is always < RX_DESC_COUNT by construction.
        let desc = unsafe { &mut *self.descriptor(self.head) };
        if desc.status & RX_STATUS_DD == 0 {
            return None;
        }
        let len = desc.length;
        let idx = self.head;
        desc.status = 0;
        self.head = (self.head + 1) % (RX_DESC_COUNT as u16);
        Some((idx, len))
    }
}
