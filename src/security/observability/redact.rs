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

extern crate alloc;

use super::policy::is_production_mode;
use alloc::string::String;

pub fn redact_pointer(ptr: usize) -> String {
    if is_production_mode() {
        String::from("[REDACTED]")
    } else {
        alloc::format!("0x{:016x}", ptr)
    }
}

pub fn redact_address(addr: u64) -> String {
    if is_production_mode() {
        String::from("[ADDR]")
    } else {
        alloc::format!("0x{:016x}", addr)
    }
}

pub fn redact_panic_message(msg: &str) -> String {
    if is_production_mode() {
        let mut redacted = String::with_capacity(msg.len());
        let mut in_path = false;
        let mut in_addr = false;

        for c in msg.chars() {
            if c == '/' || c == '\\' {
                in_path = true;
                redacted.push_str("[PATH]");
                continue;
            }
            if in_path {
                if c.is_whitespace() || c == ':' || c == ')' {
                    in_path = false;
                    redacted.push(c);
                }
                continue;
            }

            if c == '0' && !in_addr {
                in_addr = true;
                continue;
            }
            if in_addr {
                if c == 'x' || c == 'X' {
                    redacted.push_str("[ADDR]");
                    in_addr = false;
                    continue;
                }
                in_addr = false;
                redacted.push('0');
            }

            redacted.push(c);
        }
        redacted
    } else {
        String::from(msg)
    }
}
