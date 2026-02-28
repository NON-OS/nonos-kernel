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

use crate::log_info;

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::idt;
use crate::arch::x86_64::serial;
use crate::arch::x86_64::acpi;
use crate::arch::x86_64::multiboot;
use crate::arch::x86_64::pci;

pub fn init_early() {
    crate::log::init_logger();
    log_info!("Logger initialized.");

    if let Err(e) = cpu::init() {
        let _ = e;
    }
    log_info!("CPU features initialized.");

    if let Err(e) = gdt::init() {
        let _ = e;
    }
    log_info!("GDT initialized.");

    if let Err(e) = idt::init() {
        let _ = e;
    }
    log_info!("IDT initialized.");

    if let Err(e) = acpi::init() {
        let _ = e;
    }
    log_info!("ACPI tables parsed.");

    if let Err(e) = multiboot::init() {
        let _ = e;
    }
    log_info!("Multiboot info parsed.");

    if let Err(e) = serial::init() {
        let _ = e;
    }
    log_info!("Serial port initialized.");

    if let Err(e) = pci::init() {
        let _ = e;
    }
    log_info!("PCI bus scanned.");

    log_info!("Early boot initialization completed.");
}
