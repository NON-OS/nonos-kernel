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

use super::types::{
    HidDeviceType, LedState, ModifierState, MouseButtonState, KEYBOARD_REPORT_SIZE,
};

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
