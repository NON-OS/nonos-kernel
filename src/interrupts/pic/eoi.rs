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

use x86_64::instructions::port::Port;

use super::commands::EOI;
use super::ports::{MASTER_COMMAND, SLAVE_COMMAND};

#[inline]
pub fn send_eoi(irq: u8) {
    // SAFETY: Direct hardware access to send End-Of-Interrupt command.
    // Required after handling each hardware interrupt.
    unsafe {
        let mut master_cmd = Port::<u8>::new(MASTER_COMMAND);
        let mut slave_cmd = Port::<u8>::new(SLAVE_COMMAND);

        if irq >= 8 {
            slave_cmd.write(EOI);
        }
        master_cmd.write(EOI);
    }
}
