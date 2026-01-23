// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const DATA_PORT: u16 = 0x60;
pub const STATUS_PORT: u16 = 0x64;
pub const COMMAND_PORT: u16 = 0x64;

pub const STATUS_OUTPUT_FULL: u8 = 1 << 0;
pub const STATUS_INPUT_FULL: u8 = 1 << 1;
pub const STATUS_SYSTEM_FLAG: u8 = 1 << 2;
pub const STATUS_COMMAND: u8 = 1 << 3;
pub const STATUS_TIMEOUT: u8 = 1 << 6;
pub const STATUS_PARITY: u8 = 1 << 7;

pub const CMD_READ_CONFIG: u8 = 0x20;
pub const CMD_WRITE_CONFIG: u8 = 0x60;
pub const CMD_DISABLE_PORT2: u8 = 0xA7;
pub const CMD_ENABLE_PORT2: u8 = 0xA8;
pub const CMD_TEST_PORT2: u8 = 0xA9;
pub const CMD_SELF_TEST: u8 = 0xAA;
pub const CMD_TEST_PORT1: u8 = 0xAB;
pub const CMD_DISABLE_PORT1: u8 = 0xAD;
pub const CMD_ENABLE_PORT1: u8 = 0xAE;
pub const CMD_WRITE_PORT2: u8 = 0xD4;

pub const CONFIG_PORT1_IRQ: u8 = 1 << 0;
pub const CONFIG_PORT2_IRQ: u8 = 1 << 1;
pub const CONFIG_SYSTEM_FLAG: u8 = 1 << 2;
pub const CONFIG_PORT1_CLOCK: u8 = 1 << 4;
pub const CONFIG_PORT2_CLOCK: u8 = 1 << 5;
pub const CONFIG_PORT1_TRANSLATE: u8 = 1 << 6;

pub const SELF_TEST_PASS: u8 = 0x55;
pub const PORT_TEST_PASS: u8 = 0x00;

const TIMEOUT_CYCLES: u32 = 100_000;

pub struct Controller {
    dual_channel: bool,
    port1_working: bool,
    port2_working: bool,
}

impl Controller {
    pub const fn new() -> Self {
        Self {
            dual_channel: false,
            port1_working: false,
            port2_working: false,
        }
    }

    pub fn init(&mut self) -> Ps2Result<()> {
        // SAFETY: Direct port I/O for PS/2 controller initialization
        unsafe {
            outb(COMMAND_PORT, CMD_DISABLE_PORT1);
            outb(COMMAND_PORT, CMD_DISABLE_PORT2);

            while (inb(STATUS_PORT) & STATUS_OUTPUT_FULL) != 0 {
                let _ = inb(DATA_PORT);
            }

            outb(COMMAND_PORT, CMD_READ_CONFIG);
            self.wait_output()?;
            let mut config = inb(DATA_PORT);

            self.dual_channel = (config & CONFIG_PORT2_CLOCK) != 0;

            config &= !(CONFIG_PORT1_IRQ | CONFIG_PORT2_IRQ | CONFIG_PORT1_TRANSLATE);

            outb(COMMAND_PORT, CMD_WRITE_CONFIG);
            self.wait_input()?;
            outb(DATA_PORT, config);

            outb(COMMAND_PORT, CMD_SELF_TEST);
            self.wait_output()?;
            if inb(DATA_PORT) != SELF_TEST_PASS {
                return Err(Ps2Error::SelfTestFailed);
            }

            outb(COMMAND_PORT, CMD_WRITE_CONFIG);
            self.wait_input()?;
            outb(DATA_PORT, config);

            if self.dual_channel {
                outb(COMMAND_PORT, CMD_ENABLE_PORT2);
                outb(COMMAND_PORT, CMD_READ_CONFIG);
                self.wait_output()?;
                let check = inb(DATA_PORT);
                self.dual_channel = (check & CONFIG_PORT2_CLOCK) == 0;
                if self.dual_channel {
                    outb(COMMAND_PORT, CMD_DISABLE_PORT2);
                }
            }

            outb(COMMAND_PORT, CMD_TEST_PORT1);
            self.wait_output()?;
            self.port1_working = inb(DATA_PORT) == PORT_TEST_PASS;

            if self.dual_channel {
                outb(COMMAND_PORT, CMD_TEST_PORT2);
                self.wait_output()?;
                self.port2_working = inb(DATA_PORT) == PORT_TEST_PASS;
            }

            if !self.port1_working && !self.port2_working {
                return Err(Ps2Error::ControllerNotFound);
            }

            if self.port1_working {
                outb(COMMAND_PORT, CMD_ENABLE_PORT1);
                config |= CONFIG_PORT1_IRQ;
            }

            if self.port2_working {
                outb(COMMAND_PORT, CMD_ENABLE_PORT2);
                config |= CONFIG_PORT2_IRQ;
            }

            outb(COMMAND_PORT, CMD_WRITE_CONFIG);
            self.wait_input()?;
            outb(DATA_PORT, config);
        }

        Ok(())
    }

    pub fn wait_input(&self) -> Ps2Result<()> {
        for _ in 0..TIMEOUT_CYCLES {
            // SAFETY: Reading PS/2 status port
            if unsafe { inb(STATUS_PORT) } & STATUS_INPUT_FULL == 0 {
                return Ok(());
            }
        }
        Err(Ps2Error::Timeout)
    }

    pub fn wait_output(&self) -> Ps2Result<()> {
        for _ in 0..TIMEOUT_CYCLES {
            // SAFETY: Reading PS/2 status port
            if unsafe { inb(STATUS_PORT) } & STATUS_OUTPUT_FULL != 0 {
                return Ok(());
            }
        }
        Err(Ps2Error::Timeout)
    }

    pub fn read_data(&self) -> Ps2Result<u8> {
        self.wait_output()?;
        // SAFETY: Reading PS/2 data port after confirming data available
        Ok(unsafe { inb(DATA_PORT) })
    }

    pub fn write_data(&self, data: u8) -> Ps2Result<()> {
        self.wait_input()?;
        // SAFETY: Writing to PS/2 data port after confirming buffer empty
        unsafe { outb(DATA_PORT, data) };
        Ok(())
    }

    pub fn write_port2(&self, data: u8) -> Ps2Result<()> {
        if !self.port2_working {
            return Err(Ps2Error::MouseNotDetected);
        }
        self.wait_input()?;
        // SAFETY: Writing PS/2 command to redirect to port 2
        unsafe { outb(COMMAND_PORT, CMD_WRITE_PORT2) };
        self.wait_input()?;
        // SAFETY: Writing data to PS/2 port 2
        unsafe { outb(DATA_PORT, data) };
        Ok(())
    }

    pub fn send_command(&self, port: u8, cmd: u8) -> Ps2Result<u8> {
        if port == 2 {
            self.write_port2(cmd)?;
        } else {
            self.write_data(cmd)?;
        }
        self.read_data()
    }

    pub fn has_data(&self) -> bool {
        // SAFETY: Reading PS/2 status port
        (unsafe { inb(STATUS_PORT) }) & STATUS_OUTPUT_FULL != 0
    }

    pub fn read_data_nowait(&self) -> u8 {
        // SAFETY: Reading PS/2 data port
        unsafe { inb(DATA_PORT) }
    }

    pub fn is_mouse_data(&self) -> bool {
        // Bit 5 of status indicates data is from port 2 (mouse)
        // SAFETY: Reading PS/2 status port
        (unsafe { inb(STATUS_PORT) }) & (1 << 5) != 0
    }

    pub const fn port1_working(&self) -> bool {
        self.port1_working
    }

    pub const fn port2_working(&self) -> bool {
        self.port2_working
    }

    pub const fn is_dual_channel(&self) -> bool {
        self.dual_channel
    }
}

impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}
