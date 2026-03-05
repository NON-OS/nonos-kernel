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

use crate::sys::io::{inb, outb};

pub(super) fn wait_write() -> bool {
    for _ in 0..100_000 {
        // SAFETY: Reading PS/2 status port
        if unsafe { inb(0x64) } & 0x02 == 0 {
            return true;
        }
    }
    false
}

pub(super) fn wait_read() -> bool {
    for _ in 0..100_000 {
        // SAFETY: Reading PS/2 status port
        if unsafe { inb(0x64) } & 0x01 != 0 {
            return true;
        }
    }
    false
}

pub(super) fn flush_buffer() {
    for _ in 0..16 {
        // SAFETY: Reading PS/2 status and data ports
        if unsafe { inb(0x64) } & 0x01 != 0 {
            unsafe { inb(0x60); }
        } else {
            break;
        }
    }
}

pub(super) fn mouse_write(cmd: u8) -> bool {
    if !wait_write() { return false; }
    // SAFETY: Writing to PS/2 controller command port
    unsafe { outb(0x64, 0xD4); }
    if !wait_write() { return false; }
    // SAFETY: Writing to PS/2 data port
    unsafe { outb(0x60, cmd); }
    true
}

pub(super) fn mouse_read() -> Option<u8> {
    if wait_read() {
        // SAFETY: Reading from PS/2 data port
        Some(unsafe { inb(0x60) })
    } else {
        None
    }
}
