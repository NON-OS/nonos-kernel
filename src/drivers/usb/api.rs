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

use alloc::vec::Vec;

use super::device::UsbDevice;
use super::manager::{get_manager, UsbStatsSnapshot};

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
        return;
    }
    for dev in devices {
        crate::log_info!(
            "  Slot {}: {} (VID={:04x} PID={:04x})",
            dev.slot_id,
            dev.display_name(),
            dev.vendor_id(),
            dev.product_id()
        );
    }
}

pub struct UsbDeviceInfo {
    pub path: alloc::string::String,
    pub vendor_id: u16,
    pub product_id: u16,
}

pub fn list_devices() -> Vec<UsbDeviceInfo> {
    get_devices()
        .iter()
        .map(|d| UsbDeviceInfo {
            path: alloc::format!("usb{}/{}", d.slot_id / 8, d.slot_id % 8),
            vendor_id: d.vendor_id(),
            product_id: d.product_id(),
        })
        .collect()
}

pub fn bind_driver(dev_path: &str) -> Result<(), i32> {
    let parts: Vec<&str> =
        dev_path.trim_start_matches("usb").split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 {
        return Err(-22);
    }
    let slot_base: u8 = parts[0].parse().map_err(|_| -22)?;
    let slot_offset: u8 = parts[1].parse().map_err(|_| -22)?;
    let slot_id = slot_base * 8 + slot_offset;
    let devices = get_devices();
    let device = devices.iter().find(|d| d.slot_id == slot_id).ok_or(-19)?;
    super::class_driver::bind_drivers_to_device(device);
    Ok(())
}

pub fn unbind_driver(dev_path: &str) -> Result<(), i32> {
    let parts: Vec<&str> =
        dev_path.trim_start_matches("usb").split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 {
        return Err(-22);
    }
    let slot_base: u8 = parts[0].parse().map_err(|_| -22)?;
    let slot_offset: u8 = parts[1].parse().map_err(|_| -22)?;
    let slot_id = slot_base * 8 + slot_offset;
    let devices = get_devices();
    let device = devices.iter().find(|d| d.slot_id == slot_id).ok_or(-19)?;
    if let Some(cfg) = &device.active_config {
        for driver in super::class_driver::get_class_drivers() {
            for iface in &cfg.interfaces {
                if driver.matches(device, cfg, iface) {
                    driver.unbind(device, iface);
                }
            }
        }
    }
    Ok(())
}
