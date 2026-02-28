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

use core::fmt::Write;
use x86_64::instructions::port::Port;

const COM1: u16 = 0x3F8;

pub unsafe fn init_serial() { unsafe {
    // SAFETY: Writes directly to I/O ports for COM1 initialization
    let mut data = Port::<u8>::new(COM1);
    let mut ier = Port::<u8>::new(COM1 + 1);
    let mut lcr = Port::<u8>::new(COM1 + 3);
    let mut fcr = Port::<u8>::new(COM1 + 2);

    ier.write(0x00);
    lcr.write(0x80);
    data.write(0x03);
    ier.write(0x00);
    lcr.write(0x03);
    fcr.write(0xC7);
    ier.write(0x01);
}}

struct SerialWriter;

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            // SAFETY: Direct port I/O for serial transmission
            unsafe {
                let mut port = Port::<u8>::new(COM1);
                let mut lsr = Port::<u8>::new(COM1 + 5);
                while lsr.read() & 0x20 == 0 {}
                port.write(byte);
            }
        }
        Ok(())
    }
}

pub fn serial_print(args: core::fmt::Arguments) {
    let _ = SerialWriter.write_fmt(args);
}
