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

use super::{protocol, state, HidDeviceType};

pub fn get_supported_commands() -> &'static [protocol::HidCommand] { protocol::SUPPORTED_COMMANDS }
pub fn get_register_address(reg: protocol::HidRegister) -> u16 { protocol::register_address(reg) }

pub fn is_touchpad_usage(usage_page: u16, usage: u8) -> bool {
    usage_page == protocol::HID_USAGE_PAGE_DIGITIZER && usage == protocol::HID_USAGE_TOUCHPAD
}

pub fn is_touchscreen_usage(usage_page: u16, usage: u8) -> bool {
    usage_page == protocol::HID_USAGE_PAGE_DIGITIZER && usage == protocol::HID_USAGE_TOUCH_SCREEN
}

pub fn is_mouse_usage(usage_page: u16, usage: u8) -> bool {
    usage_page == protocol::HID_USAGE_PAGE_GENERIC_DESKTOP && usage == protocol::HID_USAGE_MOUSE
}

pub fn is_keyboard_usage(usage_page: u16, usage: u8) -> bool {
    usage_page == protocol::HID_USAGE_PAGE_GENERIC_DESKTOP && usage == protocol::HID_USAGE_KEYBOARD
}

pub fn touchpad_field_usages() -> (u8, u8, u8, u8, u8, u8, u8) {
    (protocol::HID_USAGE_TIP_SWITCH, protocol::HID_USAGE_CONTACT_ID, protocol::HID_USAGE_X,
     protocol::HID_USAGE_Y, protocol::HID_USAGE_CONTACT_COUNT, protocol::HID_USAGE_BUTTON_PRIMARY,
     protocol::HID_USAGE_BUTTON_SECONDARY)
}

pub fn hid_usage_pages() -> (u16, u16, u16) {
    (protocol::HID_USAGE_PAGE_DIGITIZER, protocol::HID_USAGE_PAGE_GENERIC_DESKTOP, protocol::HID_USAGE_PAGE_BUTTON)
}

pub fn init() -> usize { super::init::init() }
pub fn set_screen_bounds(width: u32, height: u32) { state::set_screen_size(width, height); }
pub fn is_available() -> bool { state::is_available() }
pub fn touchpad_available() -> bool { state::is_available() }
pub fn touchpad_working() -> bool { state::is_available() && state::get_update_count() >= 5 }
#[inline] pub fn touchpad_position() -> (i32, i32) { state::get_cursor() }
pub fn left_pressed() -> bool { state::left_pressed() }
pub fn right_pressed() -> bool { state::right_pressed() }
pub fn poll() -> bool { super::poll::poll() }
pub fn device_count() -> usize { state::device_count() }

pub fn get_device_info(index: usize) -> Option<(HidDeviceType, u16, u16)> {
    let devices = state::DEVICES.lock();
    devices.get(index).map(|dev| {
        let desc = dev.hid_descriptor();
        (dev.device_type(), desc.vendor_id, desc.product_id)
    })
}
