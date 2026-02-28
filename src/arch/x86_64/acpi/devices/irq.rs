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

use crate::arch::x86_64::acpi::parser;

pub fn irq_to_gsi(irq: u8) -> u32 {
    for ovr in parser::interrupt_overrides() {
        if ovr.source_irq == irq {
            return ovr.gsi;
        }
    }
    irq as u32
}

pub fn is_irq_level_triggered(irq: u8) -> bool {
    for ovr in parser::interrupt_overrides() {
        if ovr.source_irq == irq {
            return ovr.is_level_triggered();
        }
    }
    false
}

pub fn is_irq_active_low(irq: u8) -> bool {
    for ovr in parser::interrupt_overrides() {
        if ovr.source_irq == irq {
            return ovr.is_active_low();
        }
    }
    false
}
