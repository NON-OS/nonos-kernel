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

impl I2cHidDevice {
    pub fn is_touchpad(&self) -> bool {
        self.device_type == I2cHidDeviceType::Touchpad
    }

    pub fn is_touchscreen(&self) -> bool {
        self.device_type == I2cHidDeviceType::Touchscreen
    }
}
