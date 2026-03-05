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

use super::{i2c_hid, keyboard, mouse, usb_hid};
use keyboard::KeyEvent;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InputSource {
    PS2,
    USB,
    I2C,
}

pub struct InputManager {
    input_source: InputSource,
}

impl InputManager {
    pub fn detect() -> Self {
        let source = if i2c_hid::touchpad_available() {
            InputSource::I2C
        } else if usb_hid::is_available() {
            InputSource::USB
        } else {
            InputSource::PS2
        };

        Self { input_source: source }
    }

    pub fn source(&self) -> InputSource {
        self.input_source
    }
}

pub fn poll_keyboard_unified() -> Option<u8> {
    if usb_hid::keyboard_available() {
        if let Some(key) = usb_hid::poll_keyboard() {
            return Some(key);
        }
    }

    keyboard::poll_char()
}

pub fn poll_special_key() -> Option<KeyEvent> {
    keyboard::poll_event()
}

pub fn poll_mouse_unified() -> bool {
    i2c_hid::poll();

    if usb_hid::mouse_available() {
        usb_hid::poll_mouse();
    }

    true
}

pub fn mouse_position_unified() -> (i32, i32) {
    if mouse::is_available() {
        return mouse::position();
    }
    i2c_hid::touchpad_position()
}

pub fn left_button_pressed() -> bool {
    if mouse::is_available() {
        return mouse::left_pressed();
    }
    if usb_hid::mouse_available() {
        return usb_hid::left_pressed();
    }
    false
}

pub fn right_button_pressed() -> bool {
    if mouse::is_available() {
        return mouse::right_pressed();
    }
    if usb_hid::mouse_available() {
        return usb_hid::right_pressed();
    }
    false
}

pub fn set_screen_bounds_unified(width: u32, height: u32) {
    mouse::set_screen_bounds(width, height);
    usb_hid::set_screen_bounds(width, height);
    i2c_hid::set_screen_bounds(width, height);
}
