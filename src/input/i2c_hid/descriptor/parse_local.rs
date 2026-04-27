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

use super::parse_context::ParseContext;
use super::report_types::ReportDescriptor;
use crate::input::i2c_hid::protocol::{
    HID_USAGE_CONTACT_COUNT, HID_USAGE_CONTACT_ID, HID_USAGE_KEYBOARD, HID_USAGE_MOUSE,
    HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_GENERIC_DESKTOP, HID_USAGE_TIP_SWITCH,
    HID_USAGE_TOUCHPAD, HID_USAGE_TOUCH_SCREEN, HID_USAGE_X, HID_USAGE_Y,
};

pub(super) fn handle_local_item(
    desc: &mut ReportDescriptor,
    ctx: &mut ParseContext,
    tag: u8,
    value: u32,
) {
    if tag != 0x00 {
        return;
    }
    ctx.usage = value;
    ctx.pending_usage = Some((value, ctx.usage_page));
    if ctx.usage_page == HID_USAGE_PAGE_DIGITIZER as u32 {
        match value as u8 {
            x if x == HID_USAGE_TOUCHPAD || x == HID_USAGE_TOUCH_SCREEN => desc.has_touchpad = true,
            x if x == HID_USAGE_TIP_SWITCH => desc.has_tip = true,
            x if x == HID_USAGE_CONTACT_ID => desc.has_contact_id = true,
            x if x == HID_USAGE_CONTACT_COUNT => {
                desc.max_contact_count = ctx.logical_max.max(1).min(10) as u8;
            }
            _ => {}
        }
    }
    if ctx.usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP as u32 {
        match value as u8 {
            x if x == HID_USAGE_MOUSE => desc.has_mouse = true,
            x if x == HID_USAGE_KEYBOARD => desc.has_keyboard = true,
            x if x == HID_USAGE_X => {
                desc.has_x = true;
                if ctx.logical_max > 0 {
                    desc.logical_max_x = ctx.logical_max;
                    desc.physical_max_x = ctx.physical_max;
                }
            }
            x if x == HID_USAGE_Y => {
                desc.has_y = true;
                if ctx.logical_max > 0 {
                    desc.logical_max_y = ctx.logical_max;
                    desc.physical_max_y = ctx.physical_max;
                }
            }
            _ => {}
        }
    }
}
