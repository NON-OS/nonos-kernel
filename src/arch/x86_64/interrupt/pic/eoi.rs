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
use super::io::*;
use super::ops::read_isr_internal;

#[inline]
pub fn eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, OCW2_EOI);
        }
        outb(PIC1_CMD, OCW2_EOI);
    }
}

#[inline]
pub fn specific_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, 0x60 | (irq - 8));
            outb(PIC1_CMD, 0x60 | CASCADE_IRQ);
        } else {
            outb(PIC1_CMD, 0x60 | irq);
        }
    }
}

pub fn handle_spurious_master() -> bool {
    let (_, isr1) = read_isr_internal();

    if (isr1 & (1 << SPURIOUS_IRQ_MASTER)) != 0 {
        unsafe { outb(PIC1_CMD, OCW2_EOI); }
        true
    } else {
        false
    }
}

pub fn handle_spurious_slave() -> bool {
    let (isr2, _) = read_isr_internal();

    if (isr2 & (1 << (SPURIOUS_IRQ_SLAVE - 8))) != 0 {
        unsafe {
            outb(PIC2_CMD, OCW2_EOI);
            outb(PIC1_CMD, OCW2_EOI);
        }
        true
    } else {
        unsafe { outb(PIC1_CMD, OCW2_EOI); }
        false
    }
}
