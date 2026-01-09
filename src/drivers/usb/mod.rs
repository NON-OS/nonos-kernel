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

//! USB subsystem.

extern crate alloc;

use alloc::vec::Vec;

mod backend;
mod class_driver;
pub mod constants;
pub mod error;
mod descriptors;
mod device;
mod manager;

#[cfg(test)]
mod tests;

pub use constants::*;

pub use descriptors::{
    DeviceDescriptor, ConfigDescriptorHeader, InterfaceDescriptor, EndpointDescriptor,
    UsbStringTable, UsbInterfaceInfo, UsbConfiguration, parse_interfaces,
};

pub use device::UsbDevice;

pub use backend::{UsbHostBackend, XhciBackend};

pub use class_driver::{
    UsbClassDriver, register_class_driver, unregister_class_driver, get_class_drivers,
    bind_drivers_to_device, interface_matches, device_matches_vid_pid, device_matches_vid_pid_list,
};

pub use manager::{
    UsbManager, UsbStats, UsbStatsSnapshot,
    init_usb, get_manager, poll_endpoint,
};

pub mod consts {
    pub use super::constants::*;
}

pub fn get_devices() -> Vec<UsbDevice> {
    get_manager().map(|m| m.devices()).unwrap_or_default()
}

pub fn get_stats() -> Option<UsbStatsSnapshot> {
    get_manager().map(|m| m.stats())
}

pub fn is_initialized() -> bool {
    get_manager().is_some()
}

pub fn device_count() -> usize {
    get_manager().map(|m| m.devices().len()).unwrap_or(0)
}

pub fn find_device(vid: u16, pid: u16) -> Option<UsbDevice> {
    get_devices().into_iter().find(|d| d.matches_vid_pid(vid, pid))
}

pub fn find_devices_by_class(class: u8) -> Vec<UsbDevice> {
    get_devices().into_iter().filter(|d| d.device_class() == class).collect()
}

pub fn find_hid_devices() -> Vec<UsbDevice> {
    get_devices().into_iter().filter(|d| d.is_hid()).collect()
}

pub fn find_mass_storage_devices() -> Vec<UsbDevice> {
    get_devices().into_iter().filter(|d| d.is_mass_storage()).collect()
}

pub fn print_device_tree() {
    let devices = get_devices();
    if devices.is_empty() {
        crate::log_info!("[USB] No devices enumerated");
        return;
    }

    crate::log_info!("[USB] Enumerated devices:");
    for dev in devices {
        crate::log_info!(
            "  Slot {}: {} (VID={:04x} PID={:04x}) - {}",
            dev.slot_id,
            dev.display_name(),
            dev.vendor_id(),
            dev.product_id(),
            dev.usb_version_string()
        );

        if let Some(config) = &dev.active_config {
            for iface in &config.interfaces {
                crate::log_info!(
                    "    Interface {}: {} ({} endpoints)",
                    iface.iface.b_interface_number,
                    iface.iface.class_name(),
                    iface.endpoints.len()
                );
            }
        }
    }
}
