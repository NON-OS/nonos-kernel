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

mod constants;
mod driver;
mod keyboard;
mod mouse;
mod scancode;

pub use constants::*;
pub use driver::{device_count, get_devices, process_hid_report, register, HidDevice, HidDeviceType};
pub use keyboard::{get_led_state, poll_key, process_keyboard_report, KeyEvent, KeyboardState};
pub use mouse::{get_buttons, get_position, poll_mouse, set_screen_size, process_mouse_report, MouseEvent, MouseEventType, MouseState};
pub use scancode::{
    hid_to_ascii, identify_special_key, is_arrow_key, is_function_key, is_letter_key, is_navigation_key,
    SpecialKey, HID_TO_ASCII, HID_TO_ASCII_SHIFT,
    KEY_BACKSPACE, KEY_ENTER, KEY_ESCAPE, KEY_SPACE, KEY_TAB, KEY_CAPS_LOCK,
    KEY_NONE, KEY_ERR_ROLLOVER, KEY_A, KEY_Z, KEY_1, KEY_0,
    KEY_F1, KEY_F12, KEY_INSERT, KEY_HOME, KEY_PAGE_UP, KEY_DELETE, KEY_END, KEY_PAGE_DOWN,
    KEY_RIGHT, KEY_LEFT, KEY_DOWN, KEY_UP, is_digit_key,
};
