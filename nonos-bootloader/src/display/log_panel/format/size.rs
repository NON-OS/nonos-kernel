// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::log_panel::api::log;
use crate::display::log_panel::helpers::{copy_prefix, format_decimal};
use crate::display::log_panel::types::LogLevel;

pub fn log_size(prefix: &[u8], size: usize) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);
    pos += format_decimal(&mut buf[pos..], size);
    if pos + 6 <= buf.len() {
        buf[pos..pos + 6].copy_from_slice(b" bytes");
        pos += 6;
    }
    log(LogLevel::Ok, &buf[..pos]);
}

pub fn log_u32(prefix: &[u8], value: u32) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);
    pos += format_decimal(&mut buf[pos..], value as usize);
    log(LogLevel::Info, &buf[..pos]);
}
