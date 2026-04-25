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

use super::constants::*;
use super::io::{inb, outb};

pub fn read_irr() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
        (inb(PIC1_CMD), inb(PIC2_CMD))
    }
}

pub fn read_isr() -> (u8, u8) {
    read_isr_internal()
}

pub(crate) fn read_isr_internal() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_ISR);
        outb(PIC2_CMD, OCW3_READ_ISR);
        (inb(PIC2_CMD), inb(PIC1_CMD))
    }
}
