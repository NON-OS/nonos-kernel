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

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::pci::PciDevice;

use super::super::dma::DmaRegion;
use super::super::error::{XhciError, XhciResult};
use super::super::rings::{CommandRing, EndpointRing, EventRing};
use super::super::stats::{XhciStatistics, XhciStats};
use super::super::types::XhciConfig;

pub static XHCI_CONTROLLER: spin::Once<&'static Mutex<XhciController>> = spin::Once::new();

pub struct XhciController {
    pub(crate) _pci: PciDevice,
    pub(crate) _cap_base: usize,
    pub(crate) op_base: usize,
    pub(crate) rt_base: usize,
    pub db_base: usize,
    pub(crate) max_slots: u8,
    pub(crate) _context_size_64: bool,
    pub num_ports: u8,
    pub(crate) _version: u16,
    pub(crate) cmd_ring: CommandRing,
    pub(crate) evt_ring: EventRing,
    pub(crate) dcbaa: DmaRegion,
    pub(crate) _scratchpad_ptrs: Option<DmaRegion>,
    pub(crate) _scratchpad_buffers: Vec<DmaRegion>,
    pub(crate) device_contexts: Vec<Option<DmaRegion>>,
    pub(crate) slot_id: u8,
    pub(crate) ep0_rings: Vec<Option<EndpointRing>>,
    pub(crate) config: XhciConfig,
    pub(crate) stats: XhciStatistics,
    pub(crate) _last_enumeration_time: AtomicU64,
    pub(crate) enumeration_attempts: AtomicU64,
}

impl XhciController {
    pub fn validate_slot_id(&self, slot_id: u8) -> XhciResult<()> {
        use super::super::constants::SLOT_ID_MIN;
        if slot_id < SLOT_ID_MIN || slot_id > self.max_slots {
            self.stats.invalid_slot_errors.fetch_add(1, Ordering::Relaxed);
            return Err(XhciError::InvalidSlotId(slot_id));
        }
        Ok(())
    }

    pub fn validate_port_number(&self, port: u8) -> XhciResult<()> {
        if port < 1 || port > self.num_ports {
            self.stats.invalid_port_errors.fetch_add(1, Ordering::Relaxed);
            return Err(XhciError::InvalidPortNumber(port));
        }
        Ok(())
    }

    pub(crate) fn log_security_event(&self, event: &str) {
        if self.config.security_logging {
            self.stats.inc_security_events();
            crate::log::logger::log_critical(&alloc::format!("xHCI Security: {}", event));
        }
    }

    pub fn get_stats(&self) -> XhciStats {
        let devices = if self.slot_id > 0 { 1 } else { 0 };
        self.stats.snapshot_with_info(self.max_slots, self.num_ports, devices)
    }

    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }

    pub fn current_slot_id(&self) -> u8 {
        self.slot_id
    }

    pub fn is_slot_enabled(&self, slot_id: u8) -> bool {
        if slot_id < 1 || slot_id > self.max_slots {
            return false;
        }
        if let Some(Some(_)) = self.device_contexts.get(slot_id as usize) {
            return true;
        }
        slot_id == self.slot_id && self.slot_id > 0
    }

    pub fn get_ep0_ring(&mut self, slot_id: u8) -> Option<&mut EndpointRing> {
        self.ep0_rings.get_mut(slot_id as usize).and_then(|r| r.as_mut())
    }
}

pub fn get_controller() -> Option<spin::MutexGuard<'static, XhciController>> {
    XHCI_CONTROLLER.get().map(|m| m.lock())
}
