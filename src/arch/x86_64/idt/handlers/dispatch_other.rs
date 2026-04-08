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

use crate::arch::x86_64::idt::constants::IRQ_BASE;
use crate::arch::x86_64::idt::entry::InterruptFrame;
use crate::arch::x86_64::idt::state::{IRQ_HANDLERS, OTHER_HANDLERS, SYSCALL_HANDLER};
use super::acknowledge_interrupt;

pub(crate) fn handle_irq(frame: &mut InterruptFrame) {
    let irq = (frame.vector as u8) - IRQ_BASE;
    unsafe { if let Some(handler) = IRQ_HANDLERS[irq as usize] { handler(irq); } }
    acknowledge_interrupt(irq);
}

pub(crate) fn handle_syscall(frame: &mut InterruptFrame) {
    unsafe { if let Some(handler) = SYSCALL_HANDLER { handler(frame); } }
}

pub(crate) fn handle_other(frame: &mut InterruptFrame) {
    let vector = frame.vector as u8;
    unsafe { if let Some(handler) = OTHER_HANDLERS[vector as usize] { handler(frame); } }
}
