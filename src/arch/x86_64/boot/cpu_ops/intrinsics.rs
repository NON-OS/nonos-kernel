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
pub fn cli() {
    // SAFETY: Disabling interrupts is always valid
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn sti() {
    // SAFETY: Enabling interrupts is always valid
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn hlt() {
    // SAFETY: hlt is always valid
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn pause() {
    // SAFETY: pause is always valid
    unsafe {
        asm!("pause", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn lfence() {
    // SAFETY: lfence is always valid on x86_64
    unsafe {
        asm!("lfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn mfence() {
    // SAFETY: mfence is always valid on x86_64
    unsafe {
        asm!("mfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn sfence() {
    // SAFETY: sfence is always valid on x86_64
    unsafe {
        asm!("sfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn invlpg(addr: u64) {
    // SAFETY: invlpg with a valid address is safe
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

pub fn halt_loop() -> ! {
    loop {
        cli();
        hlt();
    }
}
