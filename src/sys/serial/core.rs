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

pub const SERIAL_PORT: u16 = 0x3F8;

pub fn init() {
    unsafe {
        outb(SERIAL_PORT + 1, 0x00);
        outb(SERIAL_PORT + 3, 0x80);
        outb(SERIAL_PORT + 0, 0x03);
        outb(SERIAL_PORT + 1, 0x00);
        outb(SERIAL_PORT + 3, 0x03);
        outb(SERIAL_PORT + 2, 0xC7);
        outb(SERIAL_PORT + 4, 0x0B);
    }
}

pub fn write_byte(ch: u8) {
    unsafe {
        while (inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        outb(SERIAL_PORT, ch);
    }
}
