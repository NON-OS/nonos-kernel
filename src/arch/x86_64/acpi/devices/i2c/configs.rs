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
use super::types::{I2cHidDevice, I2cHidDeviceType};

pub fn get_additional_touchpad_configs() -> Vec<I2cHidDevice> {
    vec![
        I2cHidDevice {
            hid: *b"FTSC1000", cid: *b"PNP0C50\0", uid: 0,
            i2c_address: 0x38, hid_desc_address: 0x0001,
            interrupt_gpio: 12, device_type: I2cHidDeviceType::Touchpad,
        },
        I2cHidDevice {
            hid: *b"MSFT0001", cid: *b"PNP0C50\0", uid: 0,
            i2c_address: 0x10, hid_desc_address: 0x0001,
            interrupt_gpio: 8, device_type: I2cHidDeviceType::Touchpad,
        },
    ]
}
