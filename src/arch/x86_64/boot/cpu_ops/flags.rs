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
pub fn read_rflags() -> u64 {
    let flags: u64;
    // SAFETY: pushfq/popfq are always valid
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, preserves_flags)
        );
    }
    flags
}

#[inline]
pub unsafe fn write_rflags(flags: u64) {
    // SAFETY: Caller ensures flags value is valid
    asm!(
        "push {}",
        "popfq",
        in(reg) flags,
        options(nomem)
    );
}
