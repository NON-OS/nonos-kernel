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

#[derive(Debug, Clone)]
pub struct I2cHidDevice {
    pub hid: [u8; 8],
    pub cid: [u8; 8],
    pub uid: u32,
    pub i2c_address: u8,
    pub hid_desc_address: u16,
    pub interrupt_gpio: u32,
    pub device_type: I2cHidDeviceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cHidDeviceType {
    Unknown,
    Touchpad,
    Touchscreen,
    Keyboard,
    Mouse,
    Stylus,
    Sensor,
}

const TOUCHPAD_HIDS: &[[u8; 8]] = &[
    *b"SYNA3602", *b"SYNA3609", *b"SYNA3619", *b"SYNA7813", *b"SYNA7817",
    *b"ELAN0001", *b"ELAN0100", *b"ELAN0600", *b"ELAN0601", *b"ELAN0602",
    *b"ELAN0603", *b"ELAN0617", *b"ELAN0618", *b"ELAN0619", *b"ELAN0620",
    *b"ELAN0621", *b"ELAN060B", *b"ELAN060C", *b"ELAN0611", *b"ELAN0612",
    *b"ELAN0650", *b"PNP0C50\0", *b"ACPI0C50", *b"MSFT0001",
    *b"ALPS0000", *b"ALPS0001", *b"CYAP0000", *b"CYAP0001", *b"FTSC1000",
];

const TOUCHSCREEN_HIDS: &[[u8; 8]] = &[
    *b"ELAN2514", *b"ELAN2097", *b"WCOM0000", *b"WCOM0001", *b"WCOM508C",
    *b"GXTP7380", *b"GXTP7386", *b"ATML1000", *b"ATML1001", *b"FTS3528\0",
];

impl I2cHidDevice {
    pub fn is_touchpad(&self) -> bool {
        self.device_type == I2cHidDeviceType::Touchpad
    }

    pub fn is_touchscreen(&self) -> bool {
        self.device_type == I2cHidDeviceType::Touchscreen
    }
}

pub fn enumerate_i2c_hid_devices() -> Vec<I2cHidDevice> {
    let mut devices = Vec::new();

    let known_touchpads = get_known_touchpad_configs();
    for tp in known_touchpads {
        devices.push(tp);
    }

    devices
}

pub fn find_touchpads() -> Vec<I2cHidDevice> {
    enumerate_i2c_hid_devices()
        .into_iter()
        .filter(|d| d.is_touchpad())
        .collect()
}

pub fn find_touchscreens() -> Vec<I2cHidDevice> {
    enumerate_i2c_hid_devices()
        .into_iter()
        .filter(|d| d.is_touchscreen())
        .collect()
}

fn get_known_touchpad_configs() -> Vec<I2cHidDevice> {
    let mut devices = Vec::new();

    devices.push(I2cHidDevice {
        hid: *b"SYNA3602",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x2C,
        hid_desc_address: 0x0020,
        interrupt_gpio: 10,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"ELAN0001",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x15,
        hid_desc_address: 0x0001,
        interrupt_gpio: 13,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"ELAN0617",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x15,
        hid_desc_address: 0x0001,
        interrupt_gpio: 14,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"SYNA7813",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x2C,
        hid_desc_address: 0x0020,
        interrupt_gpio: 15,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"ALPS0000",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x2C,
        hid_desc_address: 0x0020,
        interrupt_gpio: 9,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"CYAP0000",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x24,
        hid_desc_address: 0x0001,
        interrupt_gpio: 11,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"FTSC1000",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x38,
        hid_desc_address: 0x0001,
        interrupt_gpio: 12,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices.push(I2cHidDevice {
        hid: *b"MSFT0001",
        cid: *b"PNP0C50\0",
        uid: 0,
        i2c_address: 0x10,
        hid_desc_address: 0x0001,
        interrupt_gpio: 8,
        device_type: I2cHidDeviceType::Touchpad,
    });

    devices
}

pub fn classify_hid_device(hid: &[u8; 8]) -> I2cHidDeviceType {
    if TOUCHPAD_HIDS.contains(hid) {
        return I2cHidDeviceType::Touchpad;
    }
    if TOUCHSCREEN_HIDS.contains(hid) {
        return I2cHidDeviceType::Touchscreen;
    }

    let prefix = &hid[0..4];
    match prefix {
        b"SYNA" | b"ELAN" | b"ALPS" | b"CYAP" | b"FTSC" => I2cHidDeviceType::Touchpad,
        b"WCOM" | b"ATML" | b"GXTP" => I2cHidDeviceType::Touchscreen,
        _ => I2cHidDeviceType::Unknown,
    }
}
