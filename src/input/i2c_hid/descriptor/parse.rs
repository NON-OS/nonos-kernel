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
use super::parse_global::handle_global_item;
use super::parse_local::handle_local_item;
use super::parse_main::handle_main_item;
use super::report_types::ReportDescriptor;

impl ReportDescriptor {
    pub fn parse(data: &[u8]) -> Self {
        let mut desc = Self { data: data.to_vec(), ..Default::default() };
        let mut ctx = ParseContext::default();
        let mut i = 0;
        while i < data.len() {
            let prefix = data[i];
            if prefix == 0xFE {
                if i + 2 < data.len() {
                    i += 3 + data[i + 1] as usize;
                } else {
                    break;
                }
                continue;
            }
            let size = (prefix & 0x03) as usize;
            let actual_size = if size == 3 { 4 } else { size };
            if i + 1 + actual_size > data.len() {
                break;
            }
            let value = match actual_size {
                0 => 0u32,
                1 => data[i + 1] as u32,
                2 => u16::from_le_bytes([data[i + 1], data[i + 2]]) as u32,
                4 => u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]),
                _ => 0,
            };
            let item_type = (prefix >> 2) & 0x03;
            let tag = (prefix >> 4) & 0x0F;
            match item_type {
                0 => handle_main_item(&mut desc, &mut ctx, tag, value),
                1 => handle_global_item(&mut ctx, tag, value, actual_size),
                2 => handle_local_item(&mut desc, &mut ctx, tag, value),
                _ => {}
            }
            i += 1 + actual_size;
        }
        desc.touchpad_layout.total_report_size = ctx.current_bit_offset;
        desc
    }
}
