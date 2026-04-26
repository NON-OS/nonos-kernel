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
use crate::display::log_panel::helpers::copy_prefix;
use crate::display::log_panel::types::LogLevel;

pub const HEX: &[u8] = b"0123456789abcdef";

pub fn log_hex(prefix: &[u8], value: u64) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);
    if pos + 18 <= buf.len() {
        buf[pos] = b'0';
        buf[pos + 1] = b'x';
        pos += 2;
        for i in (0..16).rev() {
            buf[pos] = HEX[((value >> (i * 4)) & 0xF) as usize];
            pos += 1;
        }
    }
    log(LogLevel::Ok, &buf[..pos]);
}
