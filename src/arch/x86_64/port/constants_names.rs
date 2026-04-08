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

pub const fn port_name(port: u16) -> &'static str {
    match port {
        0x20 => "PIC1 Command",
        0x21 => "PIC1 Data",
        0xA0 => "PIC2 Command",
        0xA1 => "PIC2 Data",
        0x40..=0x43 => "PIT Timer",
        0x60 => "PS/2 Data",
        0x64 => "PS/2 Command/Status",
        0x70 => "CMOS Address",
        0x71 => "CMOS Data",
        0x1F0..=0x1F7 => "Primary IDE",
        0x170..=0x177 => "Secondary IDE",
        0x3F8..=0x3FF => "COM1",
        0x2F8..=0x2FF => "COM2",
        0x3E8..=0x3EF => "COM3",
        0x2E8..=0x2EF => "COM4",
        0x378..=0x37F => "LPT1",
        0x278..=0x27F => "LPT2",
        0x3C0..=0x3DF => "VGA",
        0x3F0..=0x3F7 => "Floppy",
        0xCF8 => "PCI Config Address",
        0xCFC..=0xCFF => "PCI Config Data",
        0x402 => "QEMU Debug",
        0xE9 => "Bochs Debug",
        _ => "Unknown",
    }
}
