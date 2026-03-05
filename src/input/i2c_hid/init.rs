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


use super::device::{HidDeviceType, I2cHidDevice};
use super::state;

const TOUCHPAD_ADDRESSES: &[u8] = &[
    0x15, // ELAN
    0x2C, // Synaptics
    0x10, // HP/Generic
    0x20, // Various
    0x24, // Various
    0x38, // Atmel
    0x4B, // Cypress
    0x4C, // Cypress
    0x34, // Various
    0x5C, // Various
    0x5D, // Goodix
];

pub fn init() -> usize {
    state::set_available(true);

    let (w, h) = state::get_screen_size();
    state::set_cursor(w / 2, h / 2);

    crate::log::info!("i2c_hid: init() called, cursor at ({}, {})", w/2, h/2);

    let controller_count = crate::drivers::i2c::pci::init();
    crate::log::info!("i2c_hid: {} I2C controller(s) found", controller_count);

    if controller_count == 0 {
        crate::log::info!("i2c_hid: No I2C controllers - cursor will not respond to touch");
        return 0;
    }

    let mut touchpad_count = detect_hid_devices();

    if touchpad_count == 0 {
        crate::log::info!("i2c_hid: Auto-detection failed, probing known addresses...");
        touchpad_count = probe_known_addresses(controller_count);
    }

    if touchpad_count > 0 {
        crate::log::info!("i2c_hid: {} touchpad(s) initialized successfully", touchpad_count);
    } else {
        crate::log::info!("i2c_hid: No touchpads found - cursor will not respond to touch");
    }

    touchpad_count
}

fn detect_hid_devices() -> usize {
    let detected = crate::drivers::i2c::pci::detect_hid_devices();
    let mut count = 0;

    for (controller_idx, address) in detected {
        if try_init_touchpad(controller_idx, address) {
            count += 1;
        }
    }

    count
}

fn probe_known_addresses(controller_count: usize) -> usize {
    for controller_idx in 0..controller_count {
        for &address in TOUCHPAD_ADDRESSES {
            if try_init_touchpad(controller_idx, address) {
                return 1;
            }
        }
    }
    0
}

fn try_init_touchpad(controller: usize, address: u8) -> bool {
    let mut device = match I2cHidDevice::new(controller, address) {
        Ok(dev) => dev,
        Err(_) => return false,
    };

    if device.init().is_err() {
        return false;
    }

    let device_type = device.device_type();
    if !matches!(device_type, HidDeviceType::Touchpad | HidDeviceType::Mouse) {
        return false;
    }

    let hid_desc = device.hid_descriptor();
    let report_desc = device.report_descriptor();
    crate::log::info!(
        "i2c_hid: Touchpad found - VID:0x{:04X} PID:0x{:04X}",
        hid_desc.vendor_id,
        hid_desc.product_id
    );
    crate::log::info!(
        "i2c_hid: Resolution: {}x{}, Max contacts: {}",
        report_desc.logical_max_x,
        report_desc.logical_max_y,
        report_desc.max_contact_count
    );

    state::add_device(device);

    true
}
