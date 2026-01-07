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

pub mod commands;
pub mod completion;
pub mod enumeration;
pub mod init;
pub mod ports;

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use crate::drivers::pci::PciDevice;
use super::dma::DmaRegion;
use super::error::{XhciError, XhciResult};
use super::rings::{CommandRing, EndpointRing, EventRing};
use super::stats::{XhciStatistics, XhciStats};
use super::types::XhciConfig;

pub static XHCI_CONTROLLER: spin::Once<&'static Mutex<XhciController>> = spin::Once::new();

pub struct XhciController {
    pub(crate) pci: PciDevice,
    pub(crate) cap_base: usize,
    pub(crate) op_base: usize,
    pub(crate) rt_base: usize,
    pub db_base: usize,
    pub(crate) max_slots: u8,
    pub(crate) context_size_64: bool,
    pub num_ports: u8,
    pub(crate) version: u16,
    pub(crate) cmd_ring: CommandRing,
    pub(crate) evt_ring: EventRing,
    pub(crate) dcbaa: DmaRegion,
    pub(crate) scratchpad_ptrs: Option<DmaRegion>,
    pub(crate) scratchpad_buffers: Vec<DmaRegion>,
    pub(crate) device_contexts: Vec<Option<DmaRegion>>,
    pub(crate) slot_id: u8,
    pub ep0_ring: Option<EndpointRing>,
    pub(crate) config: XhciConfig,
    pub(crate) stats: XhciStatistics,
    pub(crate) last_enumeration_time: AtomicU64,
    pub(crate) enumeration_attempts: AtomicU64,
}

impl XhciController {
    pub fn validate_slot_id(&self, slot_id: u8) -> XhciResult<()> {
        use super::constants::SLOT_ID_MIN;
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
}

pub fn get_controller() -> Option<spin::MutexGuard<'static, XhciController>> {
    XHCI_CONTROLLER.get().map(|m| m.lock())
}

pub use init::init_xhci;
