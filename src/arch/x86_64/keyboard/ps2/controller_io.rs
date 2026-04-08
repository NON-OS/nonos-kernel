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

use crate::arch::x86_64::port::{inb, outb};
use super::super::error::{Ps2Error, Ps2Result};
use super::controller_constants::*;

pub fn wait_input() -> Ps2Result<()> {
    for _ in 0..TIMEOUT_CYCLES { if unsafe { inb(STATUS_PORT) } & STATUS_INPUT_FULL == 0 { return Ok(()); } }
    Err(Ps2Error::Timeout)
}

pub fn wait_output() -> Ps2Result<()> {
    for _ in 0..TIMEOUT_CYCLES { if unsafe { inb(STATUS_PORT) } & STATUS_OUTPUT_FULL != 0 { return Ok(()); } }
    Err(Ps2Error::Timeout)
}

pub fn read_data() -> Ps2Result<u8> { wait_output()?; Ok(unsafe { inb(DATA_PORT) }) }

pub fn write_data(data: u8) -> Ps2Result<()> { wait_input()?; unsafe { outb(DATA_PORT, data) }; Ok(()) }

pub fn write_port2(data: u8) -> Ps2Result<()> {
    wait_input()?; unsafe { outb(COMMAND_PORT, CMD_WRITE_PORT2) };
    wait_input()?; unsafe { outb(DATA_PORT, data) }; Ok(())
}

pub fn has_data() -> bool { (unsafe { inb(STATUS_PORT) }) & STATUS_OUTPUT_FULL != 0 }

pub fn read_data_nowait() -> u8 { unsafe { inb(DATA_PORT) } }

pub fn is_mouse_data() -> bool { (unsafe { inb(STATUS_PORT) }) & (1 << 5) != 0 }
