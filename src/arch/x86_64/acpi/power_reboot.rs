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

use core::ptr;
use super::error::AcpiResult;
use super::parser;
use super::tables::AddressSpace;

pub fn reboot() -> AcpiResult<()> {
    if let Some(reset_performed) = parser::with_data(|data| {
        if let Some(ref reset_reg) = data.reset_reg {
            unsafe {
                match AddressSpace::from_u8(reset_reg.address_space) {
                    Some(AddressSpace::SystemIo) => {
                        crate::arch::x86_64::port::outb(reset_reg.address as u16, data.reset_value);
                        return true;
                    }
                    Some(AddressSpace::SystemMemory) => {
                        ptr::write_volatile(reset_reg.address as *mut u8, data.reset_value);
                        return true;
                    }
                    _ => {}
                }
            }
        }
        false
    }) {
        if reset_performed { for _ in 0..10000 { core::hint::spin_loop(); } }
    }
    unsafe {
        for _ in 0..1000 {
            if crate::arch::x86_64::port::inb(0x64) & 0x02 == 0 { break; }
            core::hint::spin_loop();
        }
        crate::arch::x86_64::port::outb(0x64, 0xFE);
    }
    for _ in 0..100000 { core::hint::spin_loop(); }
    unsafe {
        let null_idt: [u8; 6] = [0; 6];
        core::arch::asm!("lidt [{}]", "int3", in(reg) &null_idt, options(noreturn));
    }
}
