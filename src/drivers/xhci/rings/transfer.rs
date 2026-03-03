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

use core::{mem, ptr};

use super::super::constants::*;
use super::super::dma::DmaRegion;
use super::super::error::{XhciError, XhciResult};
use super::super::trb::{LinkTrbBuilder, Trb};

pub struct TransferRing {
    pub(super) trbs: DmaRegion,
    pub cycle: bool,
    pub(super) enqueue_index: usize,
    pub(super) ring_size: usize,
    active: bool,
}

impl TransferRing {
    pub fn new(entries: usize) -> XhciResult<Self> {
        if entries < MIN_RING_SIZE {
            return Err(XhciError::InternalError("Ring too small"));
        }
        if entries > MAX_RING_SIZE {
            return Err(XhciError::InternalError("Ring too large"));
        }

        let bytes = entries * mem::size_of::<Trb>();
        let trbs = DmaRegion::new_aligned(bytes, TRB_ALIGNMENT as usize, true)?;

        Trb::validate_pointer_alignment(trbs.phys())?;

        // SAFETY: trbs is valid allocated memory, link TRB at last position
        unsafe {
            let trb_ptr = trbs.as_mut_ptr::<Trb>();
            let link = trb_ptr.add(entries - 1);

            let link_trb = LinkTrbBuilder::new()
                .target(trbs.phys())
                .toggle_cycle(true)
                .cycle(true)
                .build();

            ptr::write_volatile(link, link_trb);
        }

        Ok(Self {
            trbs,
            cycle: true,
            enqueue_index: 0,
            ring_size: entries,
            active: false,
        })
    }

    pub fn enqueue(&mut self, mut trb: Trb) -> XhciResult<u64> {
        if self.enqueue_index == self.ring_size - 1 {
            return Err(XhciError::TrbRingFull);
        }

        trb.validate_transfer_type()?;

        trb.set_cycle(self.cycle);

        let phys = self.trbs.phys() + (self.enqueue_index * mem::size_of::<Trb>()) as u64;

        Trb::validate_pointer_alignment(phys)?;

        // SAFETY: enqueue_index validated to be within ring bounds
        unsafe {
            let ptr_trb = self.trbs.as_mut_ptr::<Trb>().add(self.enqueue_index);
            ptr::write_volatile(ptr_trb, trb);
        }

        self.enqueue_index += 1;

        if self.enqueue_index == self.ring_size - 1 {
            // SAFETY: ring_size - 1 is valid Link TRB position
            unsafe {
                let link_ptr = self.trbs.as_mut_ptr::<Trb>().add(self.ring_size - 1);
                let mut link_trb = ptr::read_volatile(link_ptr);
                link_trb.set_cycle(self.cycle);
                ptr::write_volatile(link_ptr, link_trb);
            }

            self.cycle = !self.cycle;
            self.enqueue_index = 0;
        }

        Ok(phys)
    }

    // SAFETY: Caller must ensure trb type is valid
    pub unsafe fn enqueue_raw(&mut self, mut trb: Trb) -> XhciResult<u64> {
        unsafe {
            if self.enqueue_index == self.ring_size - 1 {
                return Err(XhciError::TrbRingFull);
            }

            trb.set_cycle(self.cycle);
            let phys = self.trbs.phys() + (self.enqueue_index * mem::size_of::<Trb>()) as u64;

            let ptr_trb = self.trbs.as_mut_ptr::<Trb>().add(self.enqueue_index);
            ptr::write_volatile(ptr_trb, trb);

            self.enqueue_index += 1;
            if self.enqueue_index == self.ring_size - 1 {
                let link_ptr = self.trbs.as_mut_ptr::<Trb>().add(self.ring_size - 1);
                let mut link_trb = ptr::read_volatile(link_ptr);
                link_trb.set_cycle(self.cycle);
                ptr::write_volatile(link_ptr, link_trb);

                self.cycle = !self.cycle;
                self.enqueue_index = 0;
            }

            Ok(phys)
        }
    }

    pub fn dequeue_ptr(&self) -> u64 {
        self.trbs.phys() | (self.cycle as u64)
    }

    pub fn base_phys(&self) -> u64 {
        self.trbs.phys()
    }

    pub fn enqueue_phys(&self) -> u64 {
        self.trbs.phys() + (self.enqueue_index * mem::size_of::<Trb>()) as u64
    }

    pub fn free_count(&self) -> usize {
        self.ring_size - 1 - self.enqueue_index
    }

    pub fn is_full(&self) -> bool {
        self.enqueue_index == self.ring_size - 1
    }

    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn clear(&mut self) {
        // SAFETY: trbs is valid allocated memory
        unsafe {
            let trb_ptr = self.trbs.as_mut_ptr::<Trb>();
            for i in 0..self.ring_size - 1 {
                let trb = trb_ptr.add(i);
                (*trb).clear();
            }
        }
        self.enqueue_index = 0;
        self.cycle = true;

        // SAFETY: reinitialize Link TRB at last position
        unsafe {
            let link_ptr = self.trbs.as_mut_ptr::<Trb>().add(self.ring_size - 1);
            let link_trb = LinkTrbBuilder::new()
                .target(self.trbs.phys())
                .toggle_cycle(true)
                .cycle(true)
                .build();
            ptr::write_volatile(link_ptr, link_trb);
        }
    }

    pub fn size(&self) -> usize {
        self.ring_size
    }
}
