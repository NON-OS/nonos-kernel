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

use super::super::constants::BOOT_STACK_TOP;
use super::main_early::boot_main;

#[cfg(not(feature = "std"))]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _arch_start() -> ! {
    asm!(
        "mov rsp, {}",
        "mov rbp, rsp",
        "xor rbp, rbp",
        "call {}",
        in(reg) BOOT_STACK_TOP,
        sym boot_main,
        options(noreturn)
    );
}
