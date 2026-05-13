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

// LAPIC timer (IRQ 0 / vector 0x20). EOI is issued by the IDT IRQ
// dispatcher after this returns, so the handler only advances the
// scheduler's per-CPU tick.
pub(super) fn timer_tick(_irq: u8) {
    crate::process::scheduler::preemption::tick::tick();
}
