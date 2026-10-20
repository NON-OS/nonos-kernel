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

use super::error::AcpiResult;
use super::hw::port_bus::PortBus;
use super::hw::reset::reset_sequence;
use super::parser;

/// Reset the machine: ACPI reset register, keyboard controller, both again,
/// port 0xCF9, then a triple fault, in Linux's `reboot=acpi` order with its
/// delays (see `hw::reset`). Never returns.
pub fn reboot() -> AcpiResult<()> {
    let fadt = parser::with_data(|d| d.fadt).flatten();
    // SAFETY: CLI only masks maskable interrupts on this CPU.
    unsafe { core::arch::asm!("cli", options(nostack)) };
    reset_sequence(&mut PortBus, fadt.as_ref());
    // SAFETY: loading a zero-limit IDT and raising #BP makes the CPU fail to
    // deliver the exception, then the double fault, and shut down, which
    // the chipset turns into a reset. Nothing runs after this.
    unsafe {
        let null_idt: [u8; 10] = [0; 10];
        core::arch::asm!("lidt [{}]", "int3", in(reg) &null_idt, options(noreturn));
    }
}
