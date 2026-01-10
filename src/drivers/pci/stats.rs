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

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

static TOTAL_DEVICES: AtomicU64 = AtomicU64::new(0);
static BRIDGE_DEVICES: AtomicU64 = AtomicU64::new(0);
static MSI_CAPABLE_DEVICES: AtomicU64 = AtomicU64::new(0);
static MSIX_CAPABLE_DEVICES: AtomicU64 = AtomicU64::new(0);
static PCIE_DEVICES: AtomicU64 = AtomicU64::new(0);
static DMA_CAPABLE_DEVICES: AtomicU64 = AtomicU64::new(0);
static ENUMERATION_COUNT: AtomicU64 = AtomicU64::new(0);
static ENUMERATION_TIME_US: AtomicU64 = AtomicU64::new(0);
static CONFIG_READS: AtomicU64 = AtomicU64::new(0);
static CONFIG_WRITES: AtomicU64 = AtomicU64::new(0);
static CONFIG_ERRORS: AtomicU64 = AtomicU64::new(0);
static INTERRUPTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static MSI_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
static LEGACY_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
static HOTPLUG_EVENTS: AtomicU64 = AtomicU64::new(0);
static POWER_STATE_CHANGES: AtomicU64 = AtomicU64::new(0);
static LINK_STATE_CHANGES: AtomicU64 = AtomicU64::new(0);
static ERROR_EVENTS: AtomicU64 = AtomicU64::new(0);

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

pub fn record_device_found(
    _class: u8,
    _vendor_id: u16,
    is_bridge: bool,
    is_pcie: bool,
    has_msi: bool,
    has_msix: bool,
    is_dma_capable: bool,
) {
    TOTAL_DEVICES.fetch_add(1, Ordering::Relaxed);

    if is_bridge {
        BRIDGE_DEVICES.fetch_add(1, Ordering::Relaxed);
    }

    if is_pcie {
        PCIE_DEVICES.fetch_add(1, Ordering::Relaxed);
    }

    if has_msi {
        MSI_CAPABLE_DEVICES.fetch_add(1, Ordering::Relaxed);
    }

    if has_msix {
        MSIX_CAPABLE_DEVICES.fetch_add(1, Ordering::Relaxed);
    }

    if is_dma_capable {
        DMA_CAPABLE_DEVICES.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_enumeration(time_us: u64) {
    ENUMERATION_COUNT.fetch_add(1, Ordering::Relaxed);
    ENUMERATION_TIME_US.fetch_add(time_us, Ordering::Relaxed);
}

pub fn record_config_read() {
    CONFIG_READS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_config_write() {
    CONFIG_WRITES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_config_error() {
    CONFIG_ERRORS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_interrupt(is_msi: bool) {
    INTERRUPTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    if is_msi {
        MSI_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
    } else {
        LEGACY_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_hotplug_event() {
    HOTPLUG_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_power_state_change() {
    POWER_STATE_CHANGES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_link_state_change() {
    LINK_STATE_CHANGES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_error_event() {
    ERROR_EVENTS.fetch_add(1, Ordering::Relaxed);
}

pub fn reset_stats() {
    TOTAL_DEVICES.store(0, Ordering::Relaxed);
    BRIDGE_DEVICES.store(0, Ordering::Relaxed);
    MSI_CAPABLE_DEVICES.store(0, Ordering::Relaxed);
    MSIX_CAPABLE_DEVICES.store(0, Ordering::Relaxed);
    PCIE_DEVICES.store(0, Ordering::Relaxed);
    DMA_CAPABLE_DEVICES.store(0, Ordering::Relaxed);
    ENUMERATION_COUNT.store(0, Ordering::Relaxed);
    ENUMERATION_TIME_US.store(0, Ordering::Relaxed);
    CONFIG_READS.store(0, Ordering::Relaxed);
    CONFIG_WRITES.store(0, Ordering::Relaxed);
    CONFIG_ERRORS.store(0, Ordering::Relaxed);
    INTERRUPTS_TOTAL.store(0, Ordering::Relaxed);
    MSI_INTERRUPTS.store(0, Ordering::Relaxed);
    LEGACY_INTERRUPTS.store(0, Ordering::Relaxed);
    HOTPLUG_EVENTS.store(0, Ordering::Relaxed);
    POWER_STATE_CHANGES.store(0, Ordering::Relaxed);
    LINK_STATE_CHANGES.store(0, Ordering::Relaxed);
    ERROR_EVENTS.store(0, Ordering::Relaxed);
}

pub fn get_total_devices() -> u64 {
    TOTAL_DEVICES.load(Ordering::Relaxed)
}

pub fn get_pcie_devices() -> u64 {
    PCIE_DEVICES.load(Ordering::Relaxed)
}

pub fn get_msi_capable_devices() -> u64 {
    MSI_CAPABLE_DEVICES.load(Ordering::Relaxed)
}

pub fn get_msix_capable_devices() -> u64 {
    MSIX_CAPABLE_DEVICES.load(Ordering::Relaxed)
}

#[derive(Debug, Clone)]
pub struct DeviceClassStats {
    pub unclassified: u64,
    pub mass_storage: u64,
    pub network: u64,
    pub display: u64,
    pub multimedia: u64,
    pub memory: u64,
    pub bridge: u64,
    pub simple_comm: u64,
    pub base_peripheral: u64,
    pub input: u64,
    pub docking: u64,
    pub processor: u64,
    pub serial_bus: u64,
    pub wireless: u64,
    pub intelligent_io: u64,
    pub satellite_comm: u64,
    pub encryption: u64,
    pub signal_processing: u64,
    pub other: u64,
}

impl DeviceClassStats {
    pub fn new() -> Self {
        Self {
            unclassified: 0,
            mass_storage: 0,
            network: 0,
            display: 0,
            multimedia: 0,
            memory: 0,
            bridge: 0,
            simple_comm: 0,
            base_peripheral: 0,
            input: 0,
            docking: 0,
            processor: 0,
            serial_bus: 0,
            wireless: 0,
            intelligent_io: 0,
            satellite_comm: 0,
            encryption: 0,
            signal_processing: 0,
            other: 0,
        }
    }

    pub fn record_device(&mut self, class: u8) {
        use super::constants::*;

        match class {
            CLASS_UNCLASSIFIED => self.unclassified += 1,
            CLASS_MASS_STORAGE => self.mass_storage += 1,
            CLASS_NETWORK => self.network += 1,
            CLASS_DISPLAY => self.display += 1,
            CLASS_MULTIMEDIA => self.multimedia += 1,
            CLASS_MEMORY => self.memory += 1,
            CLASS_BRIDGE => self.bridge += 1,
            CLASS_SIMPLE_COMM => self.simple_comm += 1,
            CLASS_BASE_PERIPHERAL => self.base_peripheral += 1,
            CLASS_INPUT => self.input += 1,
            CLASS_DOCKING => self.docking += 1,
            CLASS_PROCESSOR => self.processor += 1,
            CLASS_SERIAL_BUS => self.serial_bus += 1,
            CLASS_WIRELESS => self.wireless += 1,
            CLASS_INTELLIGENT_IO => self.intelligent_io += 1,
            CLASS_SATELLITE_COMM => self.satellite_comm += 1,
            CLASS_ENCRYPTION => self.encryption += 1,
            CLASS_SIGNAL_PROCESSING => self.signal_processing += 1,
            _ => self.other += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.unclassified
            + self.mass_storage
            + self.network
            + self.display
            + self.multimedia
            + self.memory
            + self.bridge
            + self.simple_comm
            + self.base_peripheral
            + self.input
            + self.docking
            + self.processor
            + self.serial_bus
            + self.wireless
            + self.intelligent_io
            + self.satellite_comm
            + self.encryption
            + self.signal_processing
            + self.other
    }
}

impl Default for DeviceClassStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub avg_config_read_ns: u64,
    pub avg_config_write_ns: u64,
    pub enumeration_throughput: f64,
    pub interrupt_rate_per_sec: f64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            avg_config_read_ns: 0,
            avg_config_write_ns: 0,
            enumeration_throughput: 0.0,
            interrupt_rate_per_sec: 0.0,
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}
