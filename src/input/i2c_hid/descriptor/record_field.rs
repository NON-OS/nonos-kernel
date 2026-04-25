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

use super::field_location::FieldLocation;
use super::parse_context::ParseContext;
use super::report_types::ReportDescriptor;
use crate::input::i2c_hid::protocol::{
    HID_USAGE_BUTTON_PRIMARY, HID_USAGE_CONTACT_COUNT, HID_USAGE_CONTACT_ID, HID_USAGE_PAGE_BUTTON,
    HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_GENERIC_DESKTOP, HID_USAGE_TIP_SWITCH, HID_USAGE_X,
    HID_USAGE_Y,
};

pub(super) fn record_field(
    desc: &mut ReportDescriptor,
    ctx: &ParseContext,
    usage: u32,
    usage_page: u32,
    bit_offset: u16,
    bit_size: u16,
) {
    let loc = FieldLocation { bit_offset, bit_size };
    if usage_page == HID_USAGE_PAGE_DIGITIZER as u32 {
        match usage as u8 {
            0x56 => desc.touchpad_layout.scan_time = loc,
            x if x == HID_USAGE_CONTACT_COUNT => desc.touchpad_layout.contact_count = loc,
            x if x == HID_USAGE_TIP_SWITCH && ctx.in_finger && ctx.finger_index < 5 => {
                desc.touchpad_layout.contacts[ctx.finger_index].tip_switch = loc;
            }
            0x47 if ctx.in_finger && ctx.finger_index < 5 => {
                desc.touchpad_layout.contacts[ctx.finger_index].confidence = loc;
            }
            x if x == HID_USAGE_CONTACT_ID && ctx.in_finger && ctx.finger_index < 5 => {
                desc.touchpad_layout.contacts[ctx.finger_index].contact_id = loc;
            }
            0x48 if ctx.in_finger && ctx.finger_index < 5 => {
                desc.touchpad_layout.contacts[ctx.finger_index].width = loc;
            }
            0x49 if ctx.in_finger && ctx.finger_index < 5 => {
                desc.touchpad_layout.contacts[ctx.finger_index].height = loc;
            }
            0x30 if ctx.in_finger && ctx.finger_index < 5 => {
                desc.touchpad_layout.contacts[ctx.finger_index].pressure = loc;
            }
            _ => {}
        }
    }
    if usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP as u32 && ctx.in_finger && ctx.finger_index < 5
    {
        match usage as u8 {
            x if x == HID_USAGE_X => {
                desc.touchpad_layout.contacts[ctx.finger_index].x = loc;
                desc.logical_min_x = ctx.logical_min;
                desc.logical_max_x = ctx.logical_max.max(1);
            }
            x if x == HID_USAGE_Y => {
                desc.touchpad_layout.contacts[ctx.finger_index].y = loc;
                desc.logical_min_y = ctx.logical_min;
                desc.logical_max_y = ctx.logical_max.max(1);
            }
            _ => {}
        }
    }
    if usage_page == HID_USAGE_PAGE_BUTTON as u32 && usage as u8 == HID_USAGE_BUTTON_PRIMARY {
        desc.touchpad_layout.button = loc;
    }
}
