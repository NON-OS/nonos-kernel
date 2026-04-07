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

use core::arch::asm;
use crate::arch::x86_64::idt::constants::{PIC1_COMMAND, PIC2_COMMAND, PIC_EOI};
use crate::arch::x86_64::idt::entry::{InterruptFrame, PageFaultError};

#[inline]
pub(crate) fn read_cr2() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags)); }
    value
}

pub(crate) fn exception_panic(name: &str, frame: &InterruptFrame) -> ! {
    crate::sys::serial::print_str("\n!!! KERNEL PANIC: ");
    crate::sys::serial::print_str(name);
    crate::sys::serial::print_str(" !!!\nRIP=0x");
    crate::sys::serial::print_hex(frame.rip);
    crate::sys::serial::print_str(" RSP=0x");
    crate::sys::serial::print_hex(frame.rsp);
    crate::sys::serial::print_str(" ERR=0x");
    crate::sys::serial::print_hex(frame.error_code);
    crate::sys::serial::print_str("\n");
    unsafe { asm!("cli", options(nomem, nostack)); }
    loop { unsafe { asm!("hlt", options(nomem, nostack)); } }
}

pub(crate) fn exception_panic_with_cr2(name: &str, frame: &InterruptFrame, cr2: u64, error: PageFaultError) -> ! {
    crate::sys::serial::print_str("\n!!! KERNEL PANIC: ");
    crate::sys::serial::print_str(name);
    crate::sys::serial::print_str(" !!!\nRIP=0x");
    crate::sys::serial::print_hex(frame.rip);
    crate::sys::serial::print_str(" CR2=0x");
    crate::sys::serial::print_hex(cr2);
    crate::sys::serial::print_str(" ERR=0x");
    crate::sys::serial::print_hex(error.0);
    let is_present = (error.0 & 1) != 0;
    crate::sys::serial::print_str(if is_present { " P" } else { " NP" });
    if error.write() { crate::sys::serial::print_str(" W"); }
    if error.user() { crate::sys::serial::print_str(" U"); }
    crate::sys::serial::print_str("\n");
    unsafe { asm!("cli", options(nomem, nostack)); }
    loop { unsafe { asm!("hlt", options(nomem, nostack)); } }
}

pub(crate) fn send_eoi(irq: u8) {
    unsafe {
        if irq >= 8 { outb(PIC2_COMMAND, PIC_EOI); }
        outb(PIC1_COMMAND, PIC_EOI);
    }
}

#[inline]
pub(crate) unsafe fn outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

#[inline]
pub(crate) unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    value
}

#[inline]
pub(crate) fn io_wait() { unsafe { outb(0x80, 0); } }
