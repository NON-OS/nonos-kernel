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

use crate::sys::{apic, gdt, idt, serial};
use crate::{bus, interrupts};
#[cfg(feature = "nonos-legacy-tree")]
use crate::input;
use core::arch::asm;

pub fn init_core_systems() {
    serial::init();
    serial::println(b"[NONOS] Kernel entry - SSE enabled");
    crate::arch::x86_64::time::timer::init_boot_time();
    crate::sys::timer::tsc::init_default();
    unsafe {
        gdt::setup();
    }
    serial::println(b"[NONOS] GDT configured");
    unsafe {
        idt::setup();
    }
    serial::println(b"[NONOS] Early IDT configured");
    crate::memory::heap::manager::init_bootstrap();
    serial::println(b"[NONOS] Global allocator initialized");
    interrupts::init_idt();
    serial::println(b"[NONOS] Full IDT loaded");
    apic::init();
    serial::println(b"[NONOS] APIC initialized");
    // PS/2 input + IRQ wiring belongs to the legacy tree. The
    // microkernel boot path does not bring up keyboard/mouse rings;
    // input is owned by future capsule migration (input capsule).
    #[cfg(feature = "nonos-legacy-tree")]
    {
        input::keyboard::init();
        input::mouse::init();
        serial::println(b"[NONOS] Input initialized");
        apic::setup_keyboard_irq();
        apic::setup_mouse_irq();
        serial::println(b"[NONOS] IRQs enabled");
    }
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
    serial::println(b"[NONOS] Interrupts enabled");
    bus::pci::init();
    serial::println(b"[NONOS] PCI enumerated");
    init_entropy();
}

fn init_entropy() {
    if crate::drivers::init_virtio_rng().is_ok() {
        serial::println(b"[NONOS] VirtIO-RNG ready");
    } else {
        serial::println(b"[NONOS] Software RNG");
    }
}
