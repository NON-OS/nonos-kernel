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

/*
8250/16550 UART driver for COM1 debug output.

Standard PC serial port at 0x3F8, configured for 115200 baud 8N1.
Used for kernel debug logging during boot and runtime.

Many modern machines (HP Elitedesk, some Dell Optiplex, etc) ship
without a physical serial port. The line status register reads 0xFF
on these systems, so we timeout the transmit wait to avoid hanging
the boot process. Output is simply dropped if no UART is present.
*/

use spin::Mutex;

pub const SERIAL_PORT: u16 = 0x3F8;

static SERIAL_LOCK: Mutex<()> = Mutex::new(());

/*
Run one logical output unit holding the COM1 lock with interrupts
disabled, so concurrent CPUs and same-core ISRs cannot interleave
bytes mid-line. The closure must emit only through `write_byte`;
nesting another locked print inside would self-deadlock the
non-reentrant spinlock, so callers keep the byte loop inline.
*/
pub fn with_serial_lock<R>(f: impl FnOnce() -> R) -> R {
    crate::arch::run_without_interrupts(|| {
        let _guard = SERIAL_LOCK.lock();
        f()
    })
}

/*
Initialize COM1 UART at 115200 baud. Probes for hardware presence
by checking for 0xFF on the scratch register - real UARTs won't
return all-ones. Sets SERIAL_AVAILABLE flag for fast-path skip.
*/
pub fn init() {
    crate::arch::console::init();
}

/*
Write single byte to serial port. Times out after ~10000 iterations
if the transmit buffer never becomes ready - prevents infinite hang
on machines without serial hardware.
*/
pub fn write_byte(ch: u8) {
    super::tail::keep(ch);
    crate::arch::console::write_byte(ch);
}

pub fn try_write_line(bytes: &[u8]) -> bool {
    let Some(_guard) = SERIAL_LOCK.try_lock() else {
        return false;
    };
    for &ch in bytes.iter().chain(b"\r\n") {
        write_byte(ch);
    }
    true
}

pub fn is_available() -> bool {
    crate::arch::console::is_available()
}

/*
The fatal path's writer, aarch64 only. A CPU that traps while it holds
SERIAL_LOCK, or while another CPU that will never run again holds it,
would spin in with_serial_lock forever and the trap would never be
named. So the lock is taken if it frees within a bounded number of
tries, and the line is written either way: a line interleaved with
another CPU's output can still be read, a line never written cannot.
With the MMU off the lock is not touched at all. Its word is Device
memory then, and exclusive access to Device memory is not guaranteed
to work.
*/
#[cfg(target_arch = "aarch64")]
pub fn write_fatal_line(bytes: &[u8]) {
    const TRIES: u32 = 1 << 20;
    const SCTLR_M: u64 = 1;
    let sctlr: u64;
    // SAFETY: reading SCTLR_EL1 at EL1 has no side effect.
    unsafe {
        ::core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
    }
    let mut guard = None;
    if sctlr & SCTLR_M != 0 {
        for _ in 0..TRIES {
            guard = SERIAL_LOCK.try_lock();
            if guard.is_some() {
                break;
            }
            ::core::hint::spin_loop();
        }
    }
    for &ch in bytes.iter().chain(b"\r\n") {
        write_byte(ch);
    }
    drop(guard);
}
