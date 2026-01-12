// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::panic::PanicInfo;

use super::stage1::serial_print;
use super::vga;
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_print(format_args!("\n!!! KERNEL PANIC !!!\n"));
    serial_print(format_args!("{}\n", info));
    // # SAFETY: Showing panic message on VGA for diagnostics
    unsafe {
        vga::show_panic("KERNEL PANIC - See serial for details");
    }

    halt_loop()
}

#[inline(always)]
pub fn halt_loop() -> ! {
    loop {
        // # SAFETY: Disable interrupts and halt CPU in infinite loop
        unsafe {
            x86_64::instructions::interrupts::disable();
            x86_64::instructions::hlt();
        }
    }
}

#[inline]
pub fn halt() {
    // # SAFETY: Halt instruction is safe
    unsafe {
        x86_64::instructions::hlt();
    }
}

#[inline]
pub fn disable_interrupts() {
    // # SAFETY: Disabling interrupts is safe in kernel context
    unsafe {
        x86_64::instructions::interrupts::disable();
    }
}

#[inline]
pub fn enable_interrupts() {
    // # SAFETY: Enabling interrupts is safe when handlers are set up
    unsafe {
        x86_64::instructions::interrupts::enable();
    }
}

#[inline]
pub fn interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let enabled = interrupts_enabled();
    if enabled {
        disable_interrupts();
    }

    let result = f();

    if enabled {
        enable_interrupts();
    }

    result
}
