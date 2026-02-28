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

use super::super::entry::InterruptFrame;
use super::super::error::IdtError;
use super::super::state::{IRQ_HANDLERS, OTHER_HANDLERS, SYSCALL_HANDLER};

pub fn register_irq_handler(irq: u8, handler: fn(u8)) -> Result<(), IdtError> {
    if irq >= 16 {
        return Err(IdtError::InvalidVector);
    }

    // SAFETY: IRQ_HANDLERS is only modified during handler registration.
    unsafe {
        IRQ_HANDLERS[irq as usize] = Some(handler);
    }

    Ok(())
}

pub fn unregister_irq_handler(irq: u8) -> Result<(), IdtError> {
    if irq >= 16 {
        return Err(IdtError::InvalidVector);
    }

    // SAFETY: IRQ_HANDLERS is only modified during handler registration.
    unsafe {
        IRQ_HANDLERS[irq as usize] = None;
    }

    Ok(())
}

pub fn register_syscall_handler(handler: fn(&mut InterruptFrame)) {
    // SAFETY: SYSCALL_HANDLER is only modified during handler registration.
    unsafe {
        SYSCALL_HANDLER = Some(handler);
    }
}

pub fn register_handler(vector: u8, handler: fn(&mut InterruptFrame)) -> Result<(), IdtError> {
    if vector < 32 {
        return Err(IdtError::ReservedVector);
    }

    // SAFETY: OTHER_HANDLERS is only modified during handler registration.
    unsafe {
        OTHER_HANDLERS[vector as usize] = Some(handler);
    }

    Ok(())
}
