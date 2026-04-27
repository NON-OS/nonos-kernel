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

extern crate alloc;
use super::atomics::*;
use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

#[derive(Debug, Clone, Default)]
pub struct PciStats {
    pub total_devices: u64,
    pub bridge_devices: u64,
    pub msi_capable_devices: u64,
    pub msix_capable_devices: u64,
    pub pcie_devices: u64,
    pub dma_capable_devices: u64,
    pub enumeration_count: u64,
    pub enumeration_time_us: u64,
    pub config_reads: u64,
    pub config_writes: u64,
    pub config_errors: u64,
    pub interrupts_total: u64,
    pub msi_interrupts: u64,
    pub legacy_interrupts: u64,
    pub hotplug_events: u64,
    pub power_state_changes: u64,
    pub link_state_changes: u64,
    pub error_events: u64,
    pub devices_by_class: BTreeMap<u8, u64>,
    pub devices_by_vendor: BTreeMap<u16, u64>,
}

impl PciStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot() -> Self {
        Self {
            total_devices: TOTAL_DEVICES.load(Ordering::Relaxed),
            bridge_devices: BRIDGE_DEVICES.load(Ordering::Relaxed),
            msi_capable_devices: MSI_CAPABLE_DEVICES.load(Ordering::Relaxed),
            msix_capable_devices: MSIX_CAPABLE_DEVICES.load(Ordering::Relaxed),
            pcie_devices: PCIE_DEVICES.load(Ordering::Relaxed),
            dma_capable_devices: DMA_CAPABLE_DEVICES.load(Ordering::Relaxed),
            enumeration_count: ENUMERATION_COUNT.load(Ordering::Relaxed),
            enumeration_time_us: ENUMERATION_TIME_US.load(Ordering::Relaxed),
            config_reads: CONFIG_READS.load(Ordering::Relaxed),
            config_writes: CONFIG_WRITES.load(Ordering::Relaxed),
            config_errors: CONFIG_ERRORS.load(Ordering::Relaxed),
            interrupts_total: INTERRUPTS_TOTAL.load(Ordering::Relaxed),
            msi_interrupts: MSI_INTERRUPTS.load(Ordering::Relaxed),
            legacy_interrupts: LEGACY_INTERRUPTS.load(Ordering::Relaxed),
            hotplug_events: HOTPLUG_EVENTS.load(Ordering::Relaxed),
            power_state_changes: POWER_STATE_CHANGES.load(Ordering::Relaxed),
            link_state_changes: LINK_STATE_CHANGES.load(Ordering::Relaxed),
            error_events: ERROR_EVENTS.load(Ordering::Relaxed),
            devices_by_class: BTreeMap::new(),
            devices_by_vendor: BTreeMap::new(),
        }
    }

    pub fn average_enumeration_time_us(&self) -> u64 {
        if self.enumeration_count == 0 {
            0
        } else {
            self.enumeration_time_us / self.enumeration_count
        }
    }
}
