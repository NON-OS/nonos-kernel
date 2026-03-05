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

use super::{device::HidDeviceType, init, poll, protocol, state};

pub fn get_supported_commands() -> &'static [protocol::HidCommand] {
    protocol::SUPPORTED_COMMANDS
}

pub fn get_register_address(reg: protocol::HidRegister) -> u16 {
    protocol::register_address(reg)
}

pub fn is_touchpad_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_DIGITIZER && usage == HID_USAGE_TOUCHPAD
}

pub fn is_touchscreen_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_DIGITIZER && usage == HID_USAGE_TOUCH_SCREEN
}

pub fn is_mouse_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP && usage == HID_USAGE_MOUSE
}

pub fn is_keyboard_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP && usage == HID_USAGE_KEYBOARD
}

pub fn touchpad_field_usages() -> (u8, u8, u8, u8, u8, u8, u8) {
    use protocol::*;
    (
        HID_USAGE_TIP_SWITCH,
        HID_USAGE_CONTACT_ID,
        HID_USAGE_X,
        HID_USAGE_Y,
        HID_USAGE_CONTACT_COUNT,
        HID_USAGE_BUTTON_PRIMARY,
        HID_USAGE_BUTTON_SECONDARY,
    )
}

pub fn hid_usage_pages() -> (u16, u16, u16) {
    use protocol::*;
    (
        HID_USAGE_PAGE_DIGITIZER,
        HID_USAGE_PAGE_GENERIC_DESKTOP,
        HID_USAGE_PAGE_BUTTON,
    )
}

pub fn init_subsystem() -> usize {
    init::init()
}

pub fn set_screen_bounds(width: u32, height: u32) {
    state::set_screen_size(width, height);
}

pub fn is_available() -> bool {
    state::is_available()
}

pub fn touchpad_available() -> bool {
    state::is_available()
}

pub fn touchpad_working() -> bool {
    state::is_available() && state::get_update_count() >= 5
}

#[inline]
pub fn touchpad_position() -> (i32, i32) {
    state::get_cursor()
}

pub fn left_pressed() -> bool {
    false
}

pub fn right_pressed() -> bool {
    false
}

pub fn poll_touchpad() -> bool {
    poll::poll()
}

pub fn device_count() -> usize {
    state::device_count()
}

pub fn get_device_info(index: usize) -> Option<(HidDeviceType, u16, u16)> {
    let devices = state::DEVICES.lock();
    devices.get(index).map(|dev| {
        let desc = dev.hid_descriptor();
        (dev.device_type(), desc.vendor_id, desc.product_id)
    })
}

#[derive(Debug, Clone)]
pub struct TouchpadDebugInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub using_layout: bool,
    pub logical_max_x: i32,
    pub logical_max_y: i32,
    pub has_tip: bool,
    pub has_contact_id: bool,
    pub max_contacts: u8,
    pub update_count: u32,
}

pub fn get_touchpad_debug_info() -> Option<TouchpadDebugInfo> {
    let devices = state::DEVICES.lock();

    for dev in devices.iter() {
        if matches!(dev.device_type(), HidDeviceType::Touchpad | HidDeviceType::Mouse) {
            let hid_desc = dev.hid_descriptor();
            let report_desc = dev.report_descriptor();
            let (max_x, max_y) = dev.touchpad_logical_max();

            return Some(TouchpadDebugInfo {
                vendor_id: hid_desc.vendor_id,
                product_id: hid_desc.product_id,
                using_layout: dev.is_using_layout(),
                logical_max_x: max_x,
                logical_max_y: max_y,
                has_tip: report_desc.has_tip,
                has_contact_id: report_desc.has_contact_id,
                max_contacts: report_desc.max_contact_count,
                update_count: state::get_update_count(),
            });
        }
    }

    None
}
