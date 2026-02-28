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
use super::super::state::{EXCEPTION_COUNT, INITIALIZED, INTERRUPT_COUNTS, IRQ_COUNT, TOTAL_INTERRUPTS};

#[derive(Debug, Clone, Copy, Default)]
pub struct IdtStats {
    pub total_interrupts: u64,
    pub exceptions: u64,
    pub irqs: u64,
    pub initialized: bool,
}

pub fn get_stats() -> IdtStats {
    IdtStats {
        total_interrupts: TOTAL_INTERRUPTS.load(Ordering::Relaxed),
        exceptions: EXCEPTION_COUNT.load(Ordering::Relaxed),
        irqs: IRQ_COUNT.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}

pub fn get_vector_count(vector: u8) -> u64 {
    INTERRUPT_COUNTS[vector as usize].load(Ordering::Relaxed)
}
