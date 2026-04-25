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

use super::atomics::*;
use core::sync::atomic::Ordering;

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
