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
use core::panic::PanicInfo;

use super::vga;

struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        crate::sys::serial::print(s.as_bytes());
        Ok(())
    }
}

fn serial_print(args: core::fmt::Arguments<'_>) {
    let _ = SerialWriter.write_fmt(args);
}

// Panic path: serial trace, VGA banner, halt the calling CPU. SMP
// stop-the-world is documented as `SMP_UNSAFE_NEEDS_FIX` in
// `docs/hardware/cpu_smp_model.md`; on a multi-CPU boot this needs
// an NMI panic IPI before the halt, sequenced from here.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_print(format_args!("\n!!! KERNEL PANIC !!!\n"));
    serial_print(format_args!("{}\n", info));

    // SAFETY: Showing panic message on VGA for diagnostics
    unsafe {
        vga::show_panic("KERNEL PANIC - See serial for details");
    }

    crate::arch::halt_loop()
}

#[inline]
pub fn halt_loop() -> ! {
    crate::arch::halt_loop()
}

#[inline]
pub fn halt() {
    // Single-shot HLT, used by the idle hook before the panic path.
    // The cross-arch `cpu_yield` is the same primitive.
    crate::arch::cpu_yield();
}

#[inline]
pub fn disable_interrupts() {
    crate::arch::disable_interrupts()
}

#[inline]
pub fn enable_interrupts() {
    crate::arch::enable_interrupts()
}

#[inline]
pub fn interrupts_enabled() -> bool {
    crate::arch::cpu::interrupts_enabled()
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
