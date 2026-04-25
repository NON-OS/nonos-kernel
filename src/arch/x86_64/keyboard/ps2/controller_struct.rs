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

use super::super::error::{Ps2Error, Ps2Result};
use super::controller_init::init_controller;
use super::controller_io::{
    has_data as io_has, is_mouse_data as io_mouse, read_data as io_read,
    read_data_nowait as io_nowait, wait_input, wait_output, write_data as io_write,
    write_port2 as io_write_p2,
};

pub struct Controller {
    dual_channel: bool,
    port1_working: bool,
    port2_working: bool,
}

impl Controller {
    pub const fn new() -> Self {
        Self { dual_channel: false, port1_working: false, port2_working: false }
    }
    pub fn init(&mut self) -> Ps2Result<()> {
        let (d, p1, p2) = init_controller()?;
        self.dual_channel = d;
        self.port1_working = p1;
        self.port2_working = p2;
        Ok(())
    }
    pub fn wait_input(&self) -> Ps2Result<()> {
        wait_input()
    }
    pub fn wait_output(&self) -> Ps2Result<()> {
        wait_output()
    }
    pub fn read_data(&self) -> Ps2Result<u8> {
        io_read()
    }
    pub fn write_data(&self, data: u8) -> Ps2Result<()> {
        io_write(data)
    }
    pub fn write_port2(&self, data: u8) -> Ps2Result<()> {
        if !self.port2_working {
            return Err(Ps2Error::MouseNotDetected);
        }
        io_write_p2(data)
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
        io_has()
    }
    pub fn read_data_nowait(&self) -> u8 {
        io_nowait()
    }
    pub fn is_mouse_data(&self) -> bool {
        io_mouse()
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
