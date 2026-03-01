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

use super::types::{IdtPtr, IDT};

extern "C" fn default_handler() {
    unsafe {
        core::arch::asm!("iretq", options(noreturn));
    }
}

pub unsafe fn setup() {
    unsafe {
        let handler = default_handler as *const () as u64;

        let idt_ptr = &raw mut IDT;
        for i in 0..256 {
            let entry = &mut (*idt_ptr)[i];
            entry.offset_low = (handler & 0xFFFF) as u16;
            entry.selector = 0x08;
            entry.ist = 0;
            entry.type_attr = 0x8E;
            entry.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
            entry.offset_high = (handler >> 32) as u32;
            entry.zero = 0;
        }

        let ptr = IdtPtr {
            limit: 4095,
            base: (&raw const IDT) as u64,
        };

        core::arch::asm!("lidt [{0}]", in(reg) &ptr, options(nostack));
    }
}
