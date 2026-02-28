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

use super::super::stage::BootStage;
use crate::arch::x86_64::serial;

pub fn log(msg: &str) {
    if serial::is_initialized() {
        serial::write_str(msg);
    }
}

pub fn log_hex(value: u64) {
    if !serial::is_initialized() {
        return;
    }

    let hex = b"0123456789ABCDEF";
    let mut buf = [0u8; 16];

    for i in 0..16 {
        let nibble = ((value >> ((15 - i) * 4)) & 0xF) as usize;
        buf[i] = hex[nibble];
    }

    let start = buf.iter().position(|&b| b != b'0').unwrap_or(15);
    for &b in &buf[start..] {
        let _ = serial::write_byte(b);
    }
}

pub fn log_stage(stage: BootStage, success: bool) {
    if serial::is_initialized() {
        if success {
            serial::write_str("[OK] ");
        } else {
            serial::write_str("[FAIL] ");
        }
        serial::write_str(stage.as_str());
        serial::write_str("\n");
    }
}
