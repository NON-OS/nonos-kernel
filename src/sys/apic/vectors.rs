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

use super::local::TIMER_VECTOR;

pub const fn irq_to_vector(irq: u8) -> u8 {
    irq + 0x20
}

pub const IRQ_TIMER: u8 = 0;
pub const IRQ_KEYBOARD: u8 = 1;
pub const IRQ_CASCADE: u8 = 2;
pub const IRQ_COM2: u8 = 3;
pub const IRQ_COM1: u8 = 4;
pub const IRQ_LPT2: u8 = 5;
pub const IRQ_FLOPPY: u8 = 6;
pub const IRQ_LPT1: u8 = 7;
pub const IRQ_RTC: u8 = 8;
pub const IRQ_FREE1: u8 = 9;
pub const IRQ_FREE2: u8 = 10;
pub const IRQ_FREE3: u8 = 11;
pub const IRQ_MOUSE: u8 = 12;
pub const IRQ_COPROCESSOR: u8 = 13;
pub const IRQ_PRIMARY_ATA: u8 = 14;
pub const IRQ_SECONDARY_ATA: u8 = 15;

pub const VECTOR_TIMER: u8 = TIMER_VECTOR;
pub const VECTOR_KEYBOARD: u8 = 0x21;
pub const VECTOR_MOUSE: u8 = 0x2C;
pub const VECTOR_COM1: u8 = 0x24;
