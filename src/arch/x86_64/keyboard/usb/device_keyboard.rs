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

use super::device_state::HidDeviceState;
use super::types::MAX_HID_DEVICES;
use crate::arch::keyboard::{DeviceId, InputDevice, InputEvent};

pub struct UsbHidKeyboard {
    device_index: usize,
}

impl UsbHidKeyboard {
    pub const BASE_DEVICE_ID: u32 = 100;
    pub const fn new(device_index: usize) -> Self { Self { device_index } }

    pub fn first(devices: &[HidDeviceState; MAX_HID_DEVICES]) -> Option<Self> {
        for (idx, dev) in devices.iter().enumerate() {
            if dev.active && dev.device_type.is_keyboard() { return Some(Self::new(idx)); }
        }
        None
    }

    pub fn is_connected_in(&self, devices: &[HidDeviceState; MAX_HID_DEVICES]) -> bool {
        if self.device_index >= MAX_HID_DEVICES { return false; }
        devices[self.device_index].active && devices[self.device_index].device_type.is_keyboard()
    }

    pub fn device_type_in(&self, devices: &[HidDeviceState; MAX_HID_DEVICES]) -> &'static str {
        if self.device_index < MAX_HID_DEVICES && devices[self.device_index].active {
            devices[self.device_index].device_type.name()
        } else { "Disconnected" }
    }
}

impl InputDevice for UsbHidKeyboard {
    fn device_id(&self) -> DeviceId { DeviceId((Self::BASE_DEVICE_ID + self.device_index as u32) as u16) }
    fn name(&self) -> &'static str { "USB HID Keyboard" }
    fn device_type(&self) -> &'static str { "USB Keyboard" }
    fn is_connected(&self) -> bool { self.is_connected_in(&super::state::DEVICES.lock()) }
    fn poll(&self) -> Option<InputEvent> { None }
}
