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

mod common;
mod dispatch;
mod dispatch_exception;
mod dispatch_other;
mod exports;
mod isr_exceptions;
mod isr_irqs;
mod utils;
mod utils_io;
mod utils_panic;

pub(crate) use exports::*;
pub(crate) use utils::{inb, io_wait, outb};

pub(crate) fn acknowledge_interrupt(irq: u8) {
    utils::send_eoi(irq);
}
