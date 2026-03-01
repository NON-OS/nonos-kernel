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

use super::types::{GdtPtr, GDT};

pub unsafe fn setup() {
    unsafe {
        let ptr = GdtPtr {
            limit: 23,
            base: (&raw const GDT) as u64,
        };

        core::arch::asm!(
            "lgdt [{0}]",
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            in(reg) &ptr,
            options(nostack)
        );
    }
}

pub unsafe fn enable_iopl() {
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop rax",
            "or rax, 0x3000",
            "push rax",
            "popfq",
            options(nostack)
        );
    }
}
