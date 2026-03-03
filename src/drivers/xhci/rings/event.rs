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
use super::super::trb::Trb;
use super::super::types::ErstEntry;

pub struct EventRing {
    ring: DmaRegion,
    erst: DmaRegion,
    size: usize,
    dequeue_index: usize,
    pub cycle: bool,
}

impl EventRing {
    pub fn new(entries: usize) -> XhciResult<Self> {
        if entries < MIN_RING_SIZE {
            return Err(XhciError::InternalError("Event ring too small"));
        }
        if entries > MAX_RING_SIZE {
            return Err(XhciError::InternalError("Event ring too large"));
        }

        let bytes = entries * mem::size_of::<Trb>();
        let ring = DmaRegion::new_aligned(bytes, TRB_ALIGNMENT as usize, true)?;
        let erst = DmaRegion::new_aligned(mem::size_of::<ErstEntry>(), 64, true)?;

        Trb::validate_pointer_alignment(ring.phys())?;

        // SAFETY: erst is valid allocated memory for single ERST entry
        unsafe {
            let e = &mut *erst.as_mut_ptr::<ErstEntry>();
            e.ring_base_lo = (ring.phys() & 0xFFFF_FFFF) as u32;
            e.ring_base_hi = (ring.phys() >> 32) as u32;
            e.ring_size = entries as u32;
            e.reserved = 0;
        }

        Ok(Self {
            ring,
            erst,
            size: entries,
            dequeue_index: 0,
            cycle: true,
        })
    }

    pub fn trb_at(&self, idx: usize) -> Trb {
        if idx >= self.size {
            return Trb::default();
        }
        // SAFETY: idx validated to be within ring bounds
        unsafe {
            let p = self.ring.as_mut_ptr::<Trb>().add(idx);
            ptr::read_volatile(p)
        }
    }

    pub fn current_trb(&self) -> Trb {
        self.trb_at(self.dequeue_index)
    }

    pub fn has_event(&self) -> bool {
        let trb = self.current_trb();
        trb.get_cycle() == self.cycle
    }

    pub fn advance(&mut self) {
        // SAFETY: dequeue_index is within ring bounds
        unsafe {
            let p = self.ring.as_mut_ptr::<Trb>().add(self.dequeue_index);
            (*p).clear();
        }

        self.dequeue_index += 1;
        if self.dequeue_index == self.size {
            self.dequeue_index = 0;
            self.cycle = !self.cycle;
        }
    }

    pub fn current_dequeue_phys(&self) -> u64 {
        self.ring.phys() + (self.dequeue_index * mem::size_of::<Trb>()) as u64
    }

    pub fn erst_base_phys(&self) -> u64 {
        self.erst.phys()
    }

    pub fn ring_base_phys(&self) -> u64 {
        self.ring.phys()
    }

    pub fn dequeue_index(&self) -> usize {
        self.dequeue_index
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn clear(&mut self) {
        // SAFETY: ring is valid allocated memory
        unsafe {
            let trb_ptr = self.ring.as_mut_ptr::<Trb>();
            for i in 0..self.size {
                let trb = trb_ptr.add(i);
                (*trb).clear();
            }
        }
        self.dequeue_index = 0;
        self.cycle = true;
    }
}
