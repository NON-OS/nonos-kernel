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

//! Input subsystem (I2C HID, USB HID, and PS/2).

pub mod config;
pub mod i2c_hid;
pub mod keyboard;
pub mod mouse;
pub mod unified;
pub mod usb_hid;

#[cfg(test)]
pub mod tests;

pub use keyboard::{
    get_keyboard, has_data, init as keyboard_init, is_alt_pressed, is_ctrl_pressed,
    is_shift_pressed, poll as keyboard_poll, poll_char, poll_event, read_char, scancode_to_ascii,
    KeyEvent,
};

pub use mouse::{handle_interrupt, init as mouse_init, poll as mouse_poll};

pub use unified::{
    left_button_pressed, list_devices, mouse_position_unified, poll_keyboard_unified,
    poll_mouse_unified, poll_special_key, right_button_pressed, set_screen_bounds_unified,
    InputDevice, InputManager, InputSource,
};

pub use config::{
    get_keyboard_config, get_mouse_config, set_double_click_speed, set_layout, set_natural_scroll,
    set_pointer_acceleration, set_repeat_delay, set_repeat_rate, set_scroll_speed,
    set_secondary_click, set_tracking_speed, KeyboardConfig, MouseConfig, LAYOUTS,
};
