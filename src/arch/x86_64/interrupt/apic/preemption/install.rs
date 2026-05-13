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

use crate::arch::x86_64::idt::register_irq_handler;
use crate::sys::apic::vectors::IRQ_TIMER;
use crate::sys::apic::{setup_timer, stop_timer};

use super::tick_handler::timer_tick;

// 10 ms slice. Lines up with scheduler::preemption::tick's per-tick
// decrement of CURRENT_TIME_SLICE.
const TICK_HZ: u32 = 100;

// BSP path. Registers the IRQ-0 handler in the global IDT table and
// programs this CPU's LAPIC timer. APs reuse the registered handler
// and only program their own LAPIC via `install_on_ap`.
pub fn install_on_bsp() -> Result<(), &'static str> {
    register_irq_handler(IRQ_TIMER, timer_tick).map_err(|_| "irq registration failed")?;
    setup_timer(TICK_HZ);
    Ok(())
}

pub fn install_on_ap() {
    setup_timer(TICK_HZ);
}

pub fn disable() {
    stop_timer();
}
