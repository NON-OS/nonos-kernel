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

#[inline]
pub fn enable() {
    // SAFETY: Enabling interrupts via STI instruction.
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

#[inline]
pub fn disable() {
    // SAFETY: Disabling interrupts via CLI instruction.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

#[inline]
pub fn are_enabled() -> bool {
    let flags: u64;
    // SAFETY: Reading RFLAGS to check interrupt flag.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, preserves_flags)
        );
    }
    (flags & (1 << 9)) != 0
}

pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let were_enabled = are_enabled();
    disable();
    let result = f();
    if were_enabled {
        enable();
    }
    result
}
