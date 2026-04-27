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

use super::acknowledge_interrupt;
use crate::arch::x86_64::idt::constants::IRQ_BASE;
use crate::arch::x86_64::idt::entry::InterruptFrame;
use crate::arch::x86_64::idt::state::{get_irq_handler, get_other_handler, get_syscall_handler};

pub(crate) fn handle_irq(frame: &mut InterruptFrame) {
    let irq = (frame.vector as u8).wrapping_sub(IRQ_BASE);
    if let Some(handler) = get_irq_handler(irq) {
        handler(irq);
    }
    acknowledge_interrupt(irq);
}

pub(crate) fn handle_syscall(frame: &mut InterruptFrame) {
    if let Some(handler) = get_syscall_handler() {
        handler(frame);
    }
}

pub(crate) fn handle_other(frame: &mut InterruptFrame) {
    let vector = frame.vector as u8;
    if let Some(handler) = get_other_handler(vector) {
        handler(frame);
    }
}
