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
pub unsafe fn write_xcr0(value: u64) {
    // SAFETY: Caller ensures XCR0 value is valid and OSXSAVE is set
    asm!(
        "xor ecx, ecx",
        "xsetbv",
        in("eax") value as u32,
        in("edx") (value >> 32) as u32,
        out("ecx") _,
        options(nomem, nostack)
    );
}

#[inline]
pub fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Reading XCR0 requires OSXSAVE in CR4
    unsafe {
        asm!(
            "xor ecx, ecx",
            "xgetbv",
            out("eax") lo,
            out("edx") hi,
            out("ecx") _,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}
