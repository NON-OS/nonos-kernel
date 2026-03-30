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

pub(super) fn handle_global_item(ctx: &mut ParseContext, tag: u8, value: u32, actual_size: usize) {
    match tag {
        0x00 => ctx.usage_page = value,
        0x01 => {
            ctx.logical_min = if actual_size == 1 {
                (value as i8) as i32
            } else if actual_size == 2 {
                (value as i16) as i32
            } else {
                value as i32
            };
        }
        0x02 => {
            ctx.logical_max = if actual_size == 1 && (value & 0x80) != 0 {
                value as i32
            } else if actual_size == 2 {
                value as i32
            } else {
                value as i32
            };
        }
        0x04 => ctx.physical_max = value as i32,
        0x07 => ctx.report_size = value,
        0x09 => ctx.report_count = value,
        0x08 => {
            ctx.report_id = value as u8;
            ctx.current_bit_offset = 0;
        }
        _ => {}
    }
}
