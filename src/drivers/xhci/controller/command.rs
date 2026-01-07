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

use core::ptr;
use x86_64::VirtAddr;
use crate::memory::mmio::mmio_w32;
use super::super::constants::*;
use super::super::dma::DmaRegion;
use super::super::error::XhciResult;
use super::super::rings::EndpointRing;
use super::super::trb::{self, Trb};
use super::super::types::{DeviceContext, InputContext};
use super::XhciController;
impl XhciController {
    pub fn ring_doorbell(&self, slot: u8, target: u8) {
        // SAFETY: doorbell register is valid MMIO
        unsafe {
            mmio_w32(
                VirtAddr::new((self.db_base + (slot as usize) * 4) as u64),
                target as u32,
            );
        }
    }

    pub fn cmd_enqueue_and_ring(&mut self, trb: Trb) -> XhciResult<u64> {
        let ptr_phys = self.cmd_ring.enqueue(trb)?;
        self.ring_doorbell(0, 0);
        Ok(ptr_phys)
    }

    pub(crate) fn cmd_enable_slot(&mut self) -> Result<u8, &'static str> {
        let trb = trb::enable_slot_command(self.cmd_ring.cycle());
        let cmd_ptr = self.cmd_enqueue_and_ring(trb).map_err(|e| e.as_str())?;
        self.wait_command_completion(cmd_ptr)?;
        let idx = if self.evt_ring.dequeue_index() == 0 {
            self.evt_ring.size() - 1
        } else {
            self.evt_ring.dequeue_index() - 1
        };
        let evt = self.evt_ring.trb_at(idx);
        let slot_id = evt.slot_id();

        self.validate_slot_id(slot_id).map_err(|e| e.as_str())?;

        self.slot_id = slot_id;
        self.log_security_event(&alloc::format!("Enabled slot {}", slot_id));
        Ok(slot_id)
    }

    pub(crate) fn address_device(&mut self, slot_id: u8, port_id: u8) -> Result<(), &'static str> {
        self.validate_slot_id(slot_id).map_err(|e| e.as_str())?;
        self.validate_port_number(port_id).map_err(|e| e.as_str())?;

        let ic = DmaRegion::new(core::mem::size_of::<InputContext>(), true)
            .map_err(|e| e.as_str())?;

        let portsc = self.read_portsc(port_id).map_err(|e| e.as_str())?;
        let speed = ((portsc >> PORTSC_SPEED_SHIFT) & 0xF) as u8;

        let mps = match speed as u32 {
            SPEED_LOW | SPEED_FULL => MPS_FULL_SPEED,
            SPEED_HIGH => MPS_HIGH_SPEED,
            SPEED_SUPER | SPEED_SUPER_PLUS => MPS_SUPER_SPEED,
            _ => MPS_FULL_SPEED,
        };

        // SAFETY: ic is valid DMA memory
        unsafe {
            let icp = ic.as_mut_ptr::<InputContext>();
            (*icp).configure_for_address_device(port_id, speed, mps);
        }

        let dc = DmaRegion::new(core::mem::size_of::<DeviceContext>(), true)
            .map_err(|e| e.as_str())?;

        // SAFETY: dcbaa is valid DMA memory, slot_id is validated
        unsafe {
            let dcb = self.dcbaa.as_mut_ptr::<u64>().add(slot_id as usize);
            ptr::write_volatile(dcb, dc.phys());
        }

        let trb = trb::address_device_command(ic.phys(), slot_id, false, self.cmd_ring.cycle());
        let cmd_ptr = self.cmd_enqueue_and_ring(trb).map_err(|e| e.as_str())?;
        self.wait_command_completion(cmd_ptr)?;

        let mut ep0 = EndpointRing::new(64, 1).map_err(|e| e.as_str())?;
        let deq = ep0.dequeue_ptr();

        // SAFETY: dc is valid DMA memory
        unsafe {
            let dcp = dc.as_mut_ptr::<DeviceContext>();
            (*dcp).ep0.set_tr_dequeue_pointer(deq & !1, (deq & 1) != 0);
        }

        if (slot_id as usize) < self.device_contexts.len() {
            self.device_contexts[slot_id as usize] = Some(dc);
        }
        self.ep0_ring = Some(ep0);

        self.log_security_event(&alloc::format!(
            "Addressed device slot {} on port {}", slot_id, port_id
        ));
        Ok(())
    }
}
