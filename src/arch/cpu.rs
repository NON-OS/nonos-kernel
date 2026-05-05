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

//! Free-function shims that route through the active arch backend.
//!
//! Generic kernel code can call any of the names below. Internally
//! every shim dispatches through `<Arch as ArchOps>::method()` so
//! the implementation stays one place per arch.
//!
//! `init_cpu_features` is x86_64-only kernel-startup setup of CR0
//! / CR4 / XCR0 bits. It does not belong in the cross-arch trait
//! and stays here as a cfg-gated free function.

use core::arch::asm;

use super::abi::ArchOps;
use super::Arch;

#[inline(always)]
pub fn cpu_yield() {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
}

/// Enable interrupts and HLT until the next IRQ. Used by the idle
/// task; not part of the cross-arch trait because the wakeup
/// semantics differ across arches.
#[inline(always)]
pub fn idle_cpu() {
    unsafe {
        asm!("sti; hlt", options(nomem, nostack));
    }
}

#[inline(always)]
pub fn disable_interrupts() {
    unsafe { Arch::disable_interrupts() }
}

#[inline(always)]
pub fn enable_interrupts() {
    unsafe { Arch::enable_interrupts() }
}

#[inline(always)]
pub fn interrupts_enabled() -> bool {
    Arch::interrupts_enabled()
}

#[inline(always)]
pub fn get_cpu_id() -> u32 {
    Arch::current_cpu_id()
}

/// Monotonic per-CPU tick counter. Backend-defined unit.
#[inline(always)]
pub fn read_time_counter() -> u64 {
    Arch::read_time_counter()
}

/// Bring the CPU into a usable state on boot. CR0 / CR4 / XCR0 bits
/// for x87, SSE, OSXSAVE, and AVX. Kernel boot path only.
#[cfg(target_arch = "x86_64")]
pub fn init_cpu_features() {
    unsafe {
        let cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        let cr0 = (cr0 | (1 << 1)) & !(1 << 2);
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));
        let cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        let cr4 = cr4 | (1 << 9) | (1 << 10) | (1 << 18);
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));
        let mut xcr0: u64 = 1;
        xcr0 |= 1 << 1;
        xcr0 |= 1 << 2;
        asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") xcr0 as u32,
            in("edx") (xcr0 >> 32) as u32,
            options(nomem, nostack),
        );
    }
}
