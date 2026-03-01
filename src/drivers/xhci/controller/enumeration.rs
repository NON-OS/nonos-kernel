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

//! xHCI device enumeration.

use core::sync::atomic::Ordering;

use super::super::constants::*;
use super::super::dma::DmaRegion;
use super::super::error::{XhciError, XhciResult};
use super::super::trb;
use super::completion::spin_wait;
use super::XhciController;

impl XhciController {
    pub(crate) fn enumerate_all_devices(&mut self) -> Result<alloc::vec::Vec<u8>, &'static str> {
        let mut slots = alloc::vec::Vec::new();

        crate::log::logger::log_critical(&alloc::format!(
            "[xHCI] Scanning {} ports for USB devices...", self.num_ports
        ));

        for p in 1..=self.num_ports {
            let sc = self.read_portsc(p).map_err(|e| e.as_str())?;
            let connected = (sc & PORTSC_CCS) != 0;
            let enabled = (sc & PORTSC_PED) != 0;
            let speed = (sc >> PORTSC_SPEED_SHIFT) & 0xF;

            crate::log::logger::log_critical(&alloc::format!(
                "[xHCI] Port {}: PORTSC={:#010x} connected={} enabled={} speed={}",
                p, sc, connected, enabled, speed
            ));

            if connected {
                crate::log::logger::log_critical(&alloc::format!(
                    "[xHCI] Enumerating device on port {}...", p
                ));
                match self.enumerate_device_on_port(p) {
                    Ok(slot_id) => {
                        crate::log::logger::log_critical(&alloc::format!(
                            "[xHCI] Port {} -> slot {}", p, slot_id
                        ));
                        slots.push(slot_id);
                    }
                    Err(e) => {
                        crate::log::logger::log_critical(&alloc::format!(
                            "[xHCI] Port {} enumeration FAILED: {}", p, e
                        ));
                    }
                }
            }
        }

        if slots.is_empty() {
            crate::log::logger::log_critical("[xHCI] No USB devices found!");
            return Err("xHCI: no devices enumerated");
        }

        crate::log::logger::log_critical(&alloc::format!(
            "[xHCI] Successfully enumerated {} device(s)", slots.len()
        ));
        Ok(slots)
    }

    fn enumerate_device_on_port(&mut self, port: u8) -> Result<u8, &'static str> {
        self.check_enumeration_rate_limit().map_err(|e| e.as_str())?;
        self.enumeration_attempts.fetch_add(1, Ordering::Relaxed);

        self.log_security_event(&alloc::format!("Enumerating device on port {}", port));

        let mut sc = self.read_portsc(port).map_err(|e| e.as_str())?;
        sc |= PORTSC_CHANGE_BITS;
        self.write_portsc(port, sc).map_err(|e| e.as_str())?;

        sc = self.read_portsc(port).map_err(|e| e.as_str())?;
        sc = (sc & !PORTSC_PLS_MASK) | PORTSC_PR;
        self.write_portsc(port, sc).map_err(|e| e.as_str())?;

        let port_copy = port;
        if !spin_wait(
            || {
                let v = self.read_portsc(port_copy).unwrap_or(0);
                (v & PORTSC_PRC) != 0 && (v & PORTSC_PED) != 0
            },
            PORT_RESET_TIMEOUT,
        ) {
            self.stats.inc_timeouts();
            return Err("xHCI: port reset timeout");
        }

        sc = self.read_portsc(port).map_err(|e| e.as_str())?;
        sc |= PORTSC_CHANGE_BITS;
        self.write_portsc(port, sc).map_err(|e| e.as_str())?;

        let slot_id = self.cmd_enable_slot()?;
        self.address_device(slot_id, port)?;

        let mut buf = DmaRegion::new(64, true).map_err(|e| e.as_str())?;
        let _len = self.ctrl_get_descriptor_device(slot_id, &mut buf)?;
        buf.clear();

        self.stats.devices_enumerated.fetch_add(1, Ordering::Relaxed);
        Ok(slot_id)
    }

    pub(crate) fn enumerate_first_device(&mut self) -> Result<(), &'static str> {
        self.check_enumeration_rate_limit().map_err(|e| e.as_str())?;
        self.enumeration_attempts.fetch_add(1, Ordering::Relaxed);

        let mut found_port = 0u8;
        for p in 1..=self.num_ports {
            let sc = self.read_portsc(p).map_err(|e| e.as_str())?;
            if (sc & PORTSC_CCS) != 0 {
                found_port = p;
                break;
            }
        }

        if found_port == 0 {
            return Err("xHCI: no connected device on any port");
        }

        self.log_security_event(&alloc::format!("Enumerating device on port {}", found_port));

        let mut sc = self.read_portsc(found_port).map_err(|e| e.as_str())?;
        sc |= PORTSC_CHANGE_BITS;
        self.write_portsc(found_port, sc).map_err(|e| e.as_str())?;

        sc = self.read_portsc(found_port).map_err(|e| e.as_str())?;
        sc = (sc & !PORTSC_PLS_MASK) | PORTSC_PR;
        self.write_portsc(found_port, sc).map_err(|e| e.as_str())?;

        let port_copy = found_port;
        if !spin_wait(
            || {
                let v = self.read_portsc(port_copy).unwrap_or(0);
                (v & PORTSC_PRC) != 0 && (v & PORTSC_PED) != 0
            },
            PORT_RESET_TIMEOUT,
        ) {
            self.stats.inc_timeouts();
            return Err("xHCI: port reset timeout");
        }

        sc = self.read_portsc(found_port).map_err(|e| e.as_str())?;
        sc |= PORTSC_CHANGE_BITS;
        self.write_portsc(found_port, sc).map_err(|e| e.as_str())?;

        let slot_id = self.cmd_enable_slot()?;
        self.address_device(slot_id, found_port)?;

        let mut buf = DmaRegion::new(64, true).map_err(|e| e.as_str())?;
        let len = self.ctrl_get_descriptor_device(slot_id, &mut buf)?;

        crate::log::logger::log_critical(&alloc::format!(
            "xHCI: Device descriptor ({} bytes)", len
        ));

        buf.clear();

        self.stats.devices_enumerated.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn ctrl_get_descriptor_device(
        &mut self,
        slot_id: u8,
        out: &mut DmaRegion,
    ) -> Result<usize, &'static str> {
        self.validate_slot_id(slot_id).map_err(|e| e.as_str())?;

        const W_LENGTH: u16 = 18;
        out.validate_offset(0, W_LENGTH as usize).map_err(|e| e.as_str())?;

        let ep0 = self.get_ep0_ring(slot_id).ok_or("xHCI: EP0 ring not ready")?;

        let setup = trb::SetupStageTrbBuilder::new()
            .setup_packet(0x80, REQ_GET_DESCRIPTOR, 0x0100, 0x0000, W_LENGTH)
            .transfer_type(true, true)
            .cycle(ep0.cycle())
            .build();

        let data = trb::DataStageTrbBuilder::new()
            .data_buffer(out.phys(), W_LENGTH as u32)
            .direction_in(true)
            .ioc(true)
            .cycle(ep0.cycle())
            .build();

        let status = trb::StatusStageTrbBuilder::new()
            .direction_in(false)
            .cycle(ep0.cycle())
            .build();

        ep0.enqueue(setup).map_err(|e| e.as_str())?;
        ep0.enqueue(data).map_err(|e| e.as_str())?;
        let st_ptr = ep0.enqueue(status).map_err(|e| e.as_str())?;

        self.ring_doorbell(slot_id, 1);
        self.wait_transfer_completion(st_ptr)?;

        self.stats.control_transfers.fetch_add(1, Ordering::Relaxed);
        Ok(W_LENGTH as usize)
    }

    fn check_enumeration_rate_limit(&self) -> XhciResult<()> {
        if !self.config.enable_enumeration_rate_limit {
            return Ok(());
        }

        let attempts = self.enumeration_attempts.load(Ordering::Relaxed);
        if attempts >= self.config.max_enumeration_attempts as u64 {
            self.stats.enumeration_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(XhciError::EnumerationLimitExceeded);
        }

        Ok(())
    }
}
