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

use crate::arch::aarch64::asm::vectors_el1_addr;

// Install the EL1 vector table. ISB after VBAR_EL1 to serialise; any
// exception taken before this point uses whatever VBAR_EL1 the boot
// firmware left, which is undefined.
pub fn install_vbar_el1() {
    let vbar = vectors_el1_addr();
    // SAFETY: vbar is the address of an aligned static in this image.
    unsafe {
        asm!(
            "msr vbar_el1, {0}",
            "isb",
            in(reg) vbar,
            options(nostack),
        );
    }
}
