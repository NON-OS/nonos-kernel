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

use super::policy::{is_production_mode, should_emit_serial};
use super::redact::redact_panic_message;

pub fn serial_log(msg: &str) {
    if !should_emit_serial() {
        return;
    }

    for byte in msg.bytes() {
        unsafe {
            x86_64::instructions::port::Port::new(0x3F8).write(byte);
        }
    }

    unsafe {
        x86_64::instructions::port::Port::new(0x3F8).write(b'\r');
        x86_64::instructions::port::Port::new(0x3F8).write(b'\n');
    }
}

pub fn serial_log_redacted(msg: &str) {
    if !should_emit_serial() {
        return;
    }

    let output = if is_production_mode() { redact_panic_message(msg) } else { msg.into() };

    for byte in output.bytes() {
        unsafe {
            x86_64::instructions::port::Port::new(0x3F8).write(byte);
        }
    }

    unsafe {
        x86_64::instructions::port::Port::new(0x3F8).write(b'\r');
        x86_64::instructions::port::Port::new(0x3F8).write(b'\n');
    }
}
