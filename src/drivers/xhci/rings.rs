// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use super::constants::*;
use super::dma::DmaRegion;
use super::error::{XhciError, XhciResult};
use super::trb::{LinkTrbBuilder, Trb};
use super::types::ErstEntry;

pub struct TransferRing {
    trbs: DmaRegion,
    pub cycle: bool,
    enqueue_index: usize,
    ring_size: usize,
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

    pub unsafe fn enqueue_raw(&mut self, mut trb: Trb) -> XhciResult<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_constants() {
        assert!(MIN_RING_SIZE >= 16);
        assert!(MAX_RING_SIZE >= MIN_RING_SIZE);
    }
}
