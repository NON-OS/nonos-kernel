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
    // SAFETY: Reading CR2 is safe and does not modify system state.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

pub(crate) fn exception_panic(_name: &str, _frame: &InterruptFrame) -> ! {
    // SAFETY: Disabling interrupts before halt.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }

    loop {
        // SAFETY: Halting the CPU in an infinite loop.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

pub(crate) fn exception_panic_with_cr2(
    _name: &str,
    _frame: &InterruptFrame,
    _cr2: u64,
    _error: PageFaultError,
) -> ! {
    // SAFETY: Disabling interrupts before halt.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }

    loop {
        // SAFETY: Halting the CPU in an infinite loop.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

pub(crate) fn send_eoi(irq: u8) {
    // SAFETY: Writing to PIC ports to signal end of interrupt.
    unsafe {
        if irq >= 8 {
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI);
    }
}

#[inline]
pub(crate) unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port access is valid.
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub(crate) unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures port access is valid.
    let value: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

#[inline]
pub(crate) fn io_wait() {
    // SAFETY: Writing to port 0x80 is a standard I/O delay technique.
    unsafe {
        outb(0x80, 0);
    }
}
