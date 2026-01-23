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

// SAFETY: Only accesses known PCI configuration ports
#[inline]
pub fn read_u32(port: u16) -> u32 {
    unsafe {
        let value: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }
}

// SAFETY: Only accesses known PCI configuration ports
#[inline]
pub fn write_u32(port: u16, value: u32) {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
pub fn clflush(addr: usize) {
    // SAFETY: CLFLUSH is safe for flushing cache lines
    unsafe {
        core::arch::asm!(
            "clflush [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

#[inline]
pub fn mfence() {
    // SAFETY: MFENCE is always safe
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}
