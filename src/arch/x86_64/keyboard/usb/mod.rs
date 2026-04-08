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
mod device;
mod device_keyboard;
mod device_mouse;
mod device_state;
mod device_type;
mod driver;
mod enumeration;
mod error;
mod keyboard;
mod keyboard_leds;
mod keyboard_poll;
mod led_state;
mod modifier_state;
mod button_state;
mod mouse;
mod report;
mod state;
mod stats;
pub mod types;
pub mod usage;
mod usage_alpha;
mod usage_convert;
mod usage_func;
mod usage_modifiers;
mod usage_numbers;
mod usage_numpad;

pub use device::{HidDeviceState, UsbHidKeyboard, UsbHidMouse};
pub use error::{UsbHidError, UsbHidResult};
pub use driver::{init, poll, shutdown, get_device_info};
pub use enumeration::enumerate_devices;
pub use state::{device_count, get_stats, is_initialized, reset_stats};
pub use keyboard::{get_leds, set_leds};
pub use report::{
    parse_keyboard_modifiers, parse_keyboard_report, parse_keyboard_report_all,
    parse_mouse_report, parse_mouse_report_scroll,
};
pub use usage::hid_to_scancode;
pub use types::{
    HidDeviceInfo, HidDeviceType, LedState, ModifierState, MouseButtonState, UsbHidStats,
    HID_CLASS, HID_PROTOCOL_KEYBOARD, HID_PROTOCOL_MOUSE, HID_SUBCLASS_BOOT,
    KEYBOARD_REPORT_SIZE, MAX_HID_DEVICES, MAX_KEYS_PRESSED,
    MOUSE_REPORT_MIN_SIZE, MOUSE_REPORT_SCROLL_SIZE,
};
