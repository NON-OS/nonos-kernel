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

use super::types::{
    HidDeviceType, LedState, ModifierState, MouseButtonState,
    KEYBOARD_REPORT_SIZE, MAX_HID_DEVICES,
};
use crate::arch::keyboard::{DeviceId, InputDevice, InputEvent};

#[derive(Clone)]
pub struct HidDeviceState {
    pub slot_id: u8,
    pub endpoint: u8,
    pub device_type: HidDeviceType,
    pub interface: u8,
    pub active: bool,
    pub last_keyboard_report: [u8; KEYBOARD_REPORT_SIZE],
    pub modifiers: ModifierState,
    pub leds: LedState,
    pub last_mouse_buttons: MouseButtonState,
    pub report_count: u32,
    pub error_count: u32,
}

impl HidDeviceState {
    pub const fn new() -> Self {
        Self {
            slot_id: 0,
            endpoint: 0,
            device_type: HidDeviceType::Unknown,
            interface: 0,
            active: false,
            last_keyboard_report: [0; KEYBOARD_REPORT_SIZE],
            modifiers: ModifierState {
                left_ctrl: false,
                left_shift: false,
                left_alt: false,
                left_gui: false,
                right_ctrl: false,
                right_shift: false,
                right_alt: false,
                right_gui: false,
            },
            leds: LedState::new(),
            last_mouse_buttons: MouseButtonState {
                left: false,
                right: false,
                middle: false,
                button4: false,
                button5: false,
            },
            report_count: 0,
            error_count: 0,
        }
    }
}

pub struct UsbHidKeyboard {
    device_index: usize,
}

impl UsbHidKeyboard {
    pub const BASE_DEVICE_ID: u32 = 100;

    pub const fn new(device_index: usize) -> Self {
        Self { device_index }
    }

    pub fn first(devices: &[HidDeviceState; MAX_HID_DEVICES]) -> Option<Self> {
        for (idx, dev) in devices.iter().enumerate() {
            if dev.active && dev.device_type.is_keyboard() {
                return Some(Self::new(idx));
            }
        }
        None
    }

    pub fn is_connected_in(&self, devices: &[HidDeviceState; MAX_HID_DEVICES]) -> bool {
        if self.device_index >= MAX_HID_DEVICES {
            return false;
        }
        devices[self.device_index].active && devices[self.device_index].device_type.is_keyboard()
    }

    pub fn device_type_in(&self, devices: &[HidDeviceState; MAX_HID_DEVICES]) -> &'static str {
        if self.device_index < MAX_HID_DEVICES && devices[self.device_index].active {
            devices[self.device_index].device_type.name()
        } else {
            "Disconnected"
        }
    }
}

impl InputDevice for UsbHidKeyboard {
    fn device_id(&self) -> DeviceId {
        DeviceId((Self::BASE_DEVICE_ID + self.device_index as u32) as u16)
    }

    fn name(&self) -> &'static str {
        "USB HID Keyboard"
    }

    fn device_type(&self) -> &'static str {
        "USB Keyboard"
    }

    fn is_connected(&self) -> bool {
        false
    }

    fn poll(&self) -> Option<InputEvent> {
        None
    }
}

pub struct UsbHidMouse {
    device_index: usize,
}

impl UsbHidMouse {
    pub const BASE_DEVICE_ID: u32 = 200;

    pub const fn new(device_index: usize) -> Self {
        Self { device_index }
    }

    pub fn first(devices: &[HidDeviceState; MAX_HID_DEVICES]) -> Option<Self> {
        for (idx, dev) in devices.iter().enumerate() {
            if dev.active && dev.device_type.is_mouse() {
                return Some(Self::new(idx));
            }
        }
        None
    }

    pub fn is_connected_in(&self, devices: &[HidDeviceState; MAX_HID_DEVICES]) -> bool {
        if self.device_index >= MAX_HID_DEVICES {
            return false;
        }
        devices[self.device_index].active && devices[self.device_index].device_type.is_mouse()
    }

    pub fn device_type_in(&self, devices: &[HidDeviceState; MAX_HID_DEVICES]) -> &'static str {
        if self.device_index < MAX_HID_DEVICES && devices[self.device_index].active {
            devices[self.device_index].device_type.name()
        } else {
            "Disconnected"
        }
    }
}

impl InputDevice for UsbHidMouse {
    fn device_id(&self) -> DeviceId {
        DeviceId((Self::BASE_DEVICE_ID + self.device_index as u32) as u16)
    }

    fn name(&self) -> &'static str {
        "USB HID Mouse"
    }

    fn device_type(&self) -> &'static str {
        "USB Mouse"
    }

    fn is_connected(&self) -> bool {
        false
    }

    fn poll(&self) -> Option<InputEvent> {
        None
    }
}
