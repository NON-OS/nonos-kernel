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

use super::layout_types::ReportInfo;
use super::parse_context::ParseContext;
use super::record_field::record_field;
use super::report_types::ReportDescriptor;
use crate::input::i2c_hid::protocol::{
    HID_USAGE_PAGE_DIGITIZER, HID_USAGE_TOUCHPAD, HID_USAGE_TOUCH_SCREEN,
};

pub(super) fn handle_main_item(
    desc: &mut ReportDescriptor,
    ctx: &mut ParseContext,
    tag: u8,
    value: u32,
) {
    match tag {
        0x08 => {
            let bits = (ctx.report_size * ctx.report_count) as u16;
            if ctx.in_touchpad {
                if let Some((u, u_page)) = ctx.pending_usage.take() {
                    record_field(
                        desc,
                        ctx,
                        u,
                        u_page,
                        ctx.current_bit_offset,
                        ctx.report_size as u16,
                    );
                }
            }
            if ctx.report_id != 0 || bits > 0 {
                desc.input_reports.push(ReportInfo { report_id: ctx.report_id, size: bits });
            }
            ctx.current_bit_offset += bits;
        }
        0x09 => {
            let bits = (ctx.report_size * ctx.report_count) as u16;
            if ctx.report_id != 0 || bits > 0 {
                desc.output_reports.push(ReportInfo { report_id: ctx.report_id, size: bits });
            }
        }
        0x0B => {
            let bits = (ctx.report_size * ctx.report_count) as u16;
            if ctx.report_id != 0 || bits > 0 {
                desc.feature_reports.push(ReportInfo { report_id: ctx.report_id, size: bits });
            }
        }
        0x0A => handle_collection(desc, ctx, value),
        0x0C => handle_end_collection(desc, ctx),
        _ => {}
    }
}

fn handle_collection(desc: &mut ReportDescriptor, ctx: &mut ParseContext, ctype: u32) {
    if (ctype == 0x01 || ctype == 0x02) && ctx.usage_page == HID_USAGE_PAGE_DIGITIZER as u32 {
        if ctx.usage == HID_USAGE_TOUCHPAD as u32 || ctx.usage == HID_USAGE_TOUCH_SCREEN as u32 {
            ctx.in_touchpad = true;
            desc.has_touchpad = true;
            desc.touchpad_layout.report_id = ctx.report_id;
        }
    }
    if (ctype == 0x00 || ctype == 0x02)
        && ctx.usage_page == HID_USAGE_PAGE_DIGITIZER as u32
        && ctx.usage == 0x22
    {
        ctx.in_finger = true;
        ctx.finger_start_bit = ctx.current_bit_offset;
    }
}

fn handle_end_collection(desc: &mut ReportDescriptor, ctx: &mut ParseContext) {
    if ctx.in_finger {
        let finger_bits = ctx.current_bit_offset - ctx.finger_start_bit;
        if desc.touchpad_layout.contact_field_size == 0 {
            desc.touchpad_layout.contact_field_size = finger_bits;
        }
        ctx.in_finger = false;
        ctx.finger_index += 1;
    }
}
