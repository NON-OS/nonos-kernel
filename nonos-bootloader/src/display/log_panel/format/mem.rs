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

use super::hex::HEX;
use crate::display::log_panel::api::log;
use crate::display::log_panel::types::LogLevel;

pub fn log_mem(start: u64, end: u64, kind: &[u8]) {
    let mut buf = [0u8; 58];
    let mut pos = 0;
    buf[pos..pos + 2].copy_from_slice(b"0x");
    pos += 2;
    for i in (0..12).rev() {
        buf[pos] = HEX[((start >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }
    buf[pos..pos + 3].copy_from_slice(b"-0x");
    pos += 3;
    for i in (0..12).rev() {
        buf[pos] = HEX[((end >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }
    buf[pos] = b' ';
    pos += 1;
    let klen = kind.len().min(buf.len() - pos);
    buf[pos..pos + klen].copy_from_slice(&kind[..klen]);
    pos += klen;
    log(LogLevel::Info, &buf[..pos]);
}
