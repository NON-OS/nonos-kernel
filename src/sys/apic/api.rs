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

use core::sync::atomic::Ordering;
use crate::sys::serial;
use super::local::{init_local_apic, LAPIC_INIT};
use super::ioapic::{init_ioapic, enable_irq, IOAPIC_INIT};
use super::vectors::{IRQ_KEYBOARD, IRQ_MOUSE, VECTOR_KEYBOARD, VECTOR_MOUSE};

pub fn init() {
    init_local_apic();
    init_ioapic();
}

pub fn is_init() -> bool {
    LAPIC_INIT.load(Ordering::Relaxed) && IOAPIC_INIT.load(Ordering::Relaxed)
}

pub fn setup_keyboard_irq() {
    if !is_init() {
        init();
    }
    enable_irq(IRQ_KEYBOARD, VECTOR_KEYBOARD);
    serial::println(b"[APIC] Keyboard IRQ enabled");
}

pub fn setup_mouse_irq() {
    if !is_init() {
        init();
    }
    enable_irq(IRQ_MOUSE, VECTOR_MOUSE);
    serial::println(b"[APIC] Mouse IRQ enabled");
}
