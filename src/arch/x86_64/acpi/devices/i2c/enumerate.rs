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

use super::types::{I2cHidDevice, I2cHidDeviceType};
use alloc::vec::Vec;

pub fn enumerate_i2c_hid_devices() -> Vec<I2cHidDevice> {
    let mut devices = Vec::new();
    let known_touchpads = get_known_touchpad_configs();
    for tp in known_touchpads {
        devices.push(tp);
    }
    devices
}

pub fn find_touchpads() -> Vec<I2cHidDevice> {
    enumerate_i2c_hid_devices().into_iter().filter(|d| d.is_touchpad()).collect()
}

pub fn find_touchscreens() -> Vec<I2cHidDevice> {
    enumerate_i2c_hid_devices().into_iter().filter(|d| d.is_touchscreen()).collect()
}

fn get_known_touchpad_configs() -> Vec<I2cHidDevice> {
    vec![
        I2cHidDevice {
            hid: *b"SYNA3602",
            cid: *b"PNP0C50\0",
            uid: 0,
            i2c_address: 0x2C,
            hid_desc_address: 0x0020,
            interrupt_gpio: 10,
            device_type: I2cHidDeviceType::Touchpad,
        },
        I2cHidDevice {
            hid: *b"ELAN0001",
            cid: *b"PNP0C50\0",
            uid: 0,
            i2c_address: 0x15,
            hid_desc_address: 0x0001,
            interrupt_gpio: 13,
            device_type: I2cHidDeviceType::Touchpad,
        },
        I2cHidDevice {
            hid: *b"ELAN0617",
            cid: *b"PNP0C50\0",
            uid: 0,
            i2c_address: 0x15,
            hid_desc_address: 0x0001,
            interrupt_gpio: 14,
            device_type: I2cHidDeviceType::Touchpad,
        },
        I2cHidDevice {
            hid: *b"SYNA7813",
            cid: *b"PNP0C50\0",
            uid: 0,
            i2c_address: 0x2C,
            hid_desc_address: 0x0020,
            interrupt_gpio: 15,
            device_type: I2cHidDeviceType::Touchpad,
        },
        I2cHidDevice {
            hid: *b"ALPS0000",
            cid: *b"PNP0C50\0",
            uid: 0,
            i2c_address: 0x2C,
            hid_desc_address: 0x0020,
            interrupt_gpio: 9,
            device_type: I2cHidDeviceType::Touchpad,
        },
        I2cHidDevice {
            hid: *b"CYAP0000",
            cid: *b"PNP0C50\0",
            uid: 0,
            i2c_address: 0x24,
            hid_desc_address: 0x0001,
            interrupt_gpio: 11,
            device_type: I2cHidDeviceType::Touchpad,
        },
    ]
}
