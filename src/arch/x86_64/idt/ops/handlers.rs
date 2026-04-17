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
use super::super::state::{set_irq_handler, set_other_handler, set_syscall_handler};
use core::sync::atomic::Ordering;

pub fn register_irq_handler(irq: u8, handler: fn(u8)) -> Result<(), IdtError> {
    if irq >= 16 {
        return Err(IdtError::InvalidVector);
    }
    set_irq_handler(irq, handler);
    Ok(())
}

pub fn unregister_irq_handler(irq: u8) -> Result<(), IdtError> {
    if irq >= 16 {
        return Err(IdtError::InvalidVector);
    }
    super::super::state::IRQ_HANDLERS[irq as usize].store(core::ptr::null_mut(), Ordering::Release);
    Ok(())
}

pub fn register_syscall_handler(handler: fn(&mut InterruptFrame)) {
    set_syscall_handler(handler);
}

pub fn register_handler(vector: u8, handler: fn(&mut InterruptFrame)) -> Result<(), IdtError> {
    if vector < 32 {
        return Err(IdtError::ReservedVector);
    }
    set_other_handler(vector, handler);
    Ok(())
}
