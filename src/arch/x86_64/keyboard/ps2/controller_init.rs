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
use super::controller_io::{wait_input, wait_output};

pub fn init_controller() -> Ps2Result<(bool, bool, bool)> {
    unsafe {
        outb(COMMAND_PORT, CMD_DISABLE_PORT1);
        outb(COMMAND_PORT, CMD_DISABLE_PORT2);
        while (inb(STATUS_PORT) & STATUS_OUTPUT_FULL) != 0 { let _ = inb(DATA_PORT); }
        outb(COMMAND_PORT, CMD_READ_CONFIG);
        wait_output()?;
        let mut config = inb(DATA_PORT);
        let dual_channel = (config & CONFIG_PORT2_CLOCK) != 0;
        config &= !(CONFIG_PORT1_IRQ | CONFIG_PORT2_IRQ | CONFIG_PORT1_TRANSLATE);
        outb(COMMAND_PORT, CMD_WRITE_CONFIG); wait_input()?; outb(DATA_PORT, config);
        outb(COMMAND_PORT, CMD_SELF_TEST); wait_output()?;
        if inb(DATA_PORT) != SELF_TEST_PASS { return Err(Ps2Error::SelfTestFailed); }
        outb(COMMAND_PORT, CMD_WRITE_CONFIG); wait_input()?; outb(DATA_PORT, config);
        let dual_ch = check_dual_channel(dual_channel)?;
        let port1_ok = test_port1()?;
        let port2_ok = if dual_ch { test_port2()? } else { false };
        if !port1_ok && !port2_ok { return Err(Ps2Error::ControllerNotFound); }
        enable_ports(port1_ok, port2_ok, &mut config)?;
        Ok((dual_ch, port1_ok, port2_ok))
    }
}

unsafe fn check_dual_channel(mut dual: bool) -> Ps2Result<bool> {
    if dual {
        outb(COMMAND_PORT, CMD_ENABLE_PORT2);
        outb(COMMAND_PORT, CMD_READ_CONFIG);
        wait_output()?;
        let check = inb(DATA_PORT);
        dual = (check & CONFIG_PORT2_CLOCK) == 0;
        if dual { outb(COMMAND_PORT, CMD_DISABLE_PORT2); }
    }
    Ok(dual)
}

unsafe fn test_port1() -> Ps2Result<bool> {
    outb(COMMAND_PORT, CMD_TEST_PORT1);
    wait_output()?;
    Ok(inb(DATA_PORT) == PORT_TEST_PASS)
}

unsafe fn test_port2() -> Ps2Result<bool> {
    outb(COMMAND_PORT, CMD_TEST_PORT2);
    wait_output()?;
    Ok(inb(DATA_PORT) == PORT_TEST_PASS)
}

unsafe fn enable_ports(p1: bool, p2: bool, config: &mut u8) -> Ps2Result<()> {
    if p1 { outb(COMMAND_PORT, CMD_ENABLE_PORT1); *config |= CONFIG_PORT1_IRQ; }
    if p2 { outb(COMMAND_PORT, CMD_ENABLE_PORT2); *config |= CONFIG_PORT2_IRQ; }
    outb(COMMAND_PORT, CMD_WRITE_CONFIG); wait_input()?; outb(DATA_PORT, *config); Ok(())
}
