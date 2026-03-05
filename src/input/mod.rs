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

pub mod i2c_hid;
pub mod keyboard;
pub mod mouse;
pub mod unified;
pub mod usb_hid;

pub use keyboard::{
    init as keyboard_init, poll as keyboard_poll, scancode_to_ascii, poll_char,
    has_data, read_char, is_shift_pressed, is_ctrl_pressed, is_alt_pressed,
    get_keyboard, poll_event, KeyEvent,
};

pub use mouse::{init as mouse_init, poll as mouse_poll, handle_interrupt};

pub use unified::{
    InputSource, InputManager, poll_keyboard_unified, poll_special_key,
    poll_mouse_unified, mouse_position_unified, left_button_pressed,
    right_button_pressed, set_screen_bounds_unified,
};
