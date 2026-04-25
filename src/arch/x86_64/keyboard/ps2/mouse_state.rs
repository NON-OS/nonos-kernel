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
use super::controller::Controller;
use super::mouse_commands::CMD_SET_RESOLUTION;
use super::mouse_init::init_mouse;
use super::mouse_parse::parse_packet;
use super::mouse_types::{MousePacket, MouseType, Resolution};

pub struct Mouse {
    detected: bool,
    mouse_type: MouseType,
    packet_buffer: [u8; 4],
    packet_index: usize,
}

impl Mouse {
    pub const fn new() -> Self {
        Self {
            detected: false,
            mouse_type: MouseType::Standard,
            packet_buffer: [0; 4],
            packet_index: 0,
        }
    }
    pub fn init(&mut self, controller: &Controller) -> Ps2Result<()> {
        self.mouse_type = init_mouse(controller)?;
        self.detected = true;
        Ok(())
    }
    pub fn process_byte(&mut self, byte: u8) -> Option<MousePacket> {
        if self.packet_index == 0 && (byte & 0x08) == 0 {
            return None;
        }
        self.packet_buffer[self.packet_index] = byte;
        self.packet_index += 1;
        if self.packet_index >= self.mouse_type.packet_size() {
            self.packet_index = 0;
            return Some(parse_packet(&self.packet_buffer, self.mouse_type));
        }
        None
    }
    pub fn set_resolution(&self, controller: &Controller, resolution: Resolution) -> Ps2Result<()> {
        if !self.detected {
            return Err(Ps2Error::MouseNotDetected);
        }
        controller.write_port2(CMD_SET_RESOLUTION)?;
        let _ = controller.read_data()?;
        controller.write_port2(resolution as u8)?;
        let _ = controller.read_data()?;
        Ok(())
    }
    pub fn reset_packet_state(&mut self) {
        self.packet_index = 0;
    }
    pub const fn is_detected(&self) -> bool {
        self.detected
    }
    pub const fn mouse_type(&self) -> MouseType {
        self.mouse_type
    }
}

impl Default for Mouse {
    fn default() -> Self {
        Self::new()
    }
}
