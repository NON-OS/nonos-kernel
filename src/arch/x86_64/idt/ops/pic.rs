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

use super::super::constants::*;
use super::super::handlers::{inb, outb, io_wait};

pub fn remap_pic() {
    // SAFETY: Remapping PIC during initialization.
    unsafe {
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        outb(PIC1_COMMAND, ICW1_INIT);
        io_wait();
        outb(PIC2_COMMAND, ICW1_INIT);
        io_wait();

        outb(PIC1_DATA, IRQ_BASE);
        io_wait();
        outb(PIC2_DATA, IRQ_BASE + 8);
        io_wait();

        outb(PIC1_DATA, 4);
        io_wait();
        outb(PIC2_DATA, 2);
        io_wait();

        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);
    }
}

pub fn disable_pic() {
    // SAFETY: Disabling PIC by masking all interrupts.
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

pub fn set_pic_masks(mask1: u8, mask2: u8) {
    // SAFETY: Setting PIC masks.
    unsafe {
        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);
    }
}

pub fn get_pic_masks() -> (u8, u8) {
    // SAFETY: Reading PIC masks.
    unsafe { (inb(PIC1_DATA), inb(PIC2_DATA)) }
}
