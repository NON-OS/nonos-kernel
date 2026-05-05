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

use crate::interrupts::apic;
use crate::interrupts::pic;
use crate::interrupts::safety::set_interrupt_context;
use crate::interrupts::stats;

const KEYBOARD_IRQ_LINE: u8 = 1;

/// # Safety
/// Keyboard interrupt handler. Sets interrupt context for safe nesting detection.
pub fn handle() {
    let _ctx = set_interrupt_context();

    // The PS/2 keyboard driver lives in the legacy tree. The IDT slot
    // for `VECTOR_KEYBOARD` still has to resolve to a symbol, but the
    // microkernel build owns no scancode pipeline; just acknowledge.

    stats::increment_keyboard();

    send_eoi();
}

fn send_eoi() {
    if apic::is_enabled() {
        apic::send_eoi();
    } else {
        pic::send_eoi(KEYBOARD_IRQ_LINE);
    }
}
