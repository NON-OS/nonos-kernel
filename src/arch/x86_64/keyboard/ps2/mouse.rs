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

use super::controller::Controller;
use super::super::error::{Ps2Error, Ps2Result};
use super::super::types::MouseButtons;

pub const CMD_SET_SCALING_1_1: u8 = 0xE6;
pub const CMD_SET_SCALING_2_1: u8 = 0xE7;
pub const CMD_SET_RESOLUTION: u8 = 0xE8;
pub const CMD_STATUS_REQUEST: u8 = 0xE9;
pub const CMD_SET_STREAM_MODE: u8 = 0xEA;
pub const CMD_READ_DATA: u8 = 0xEB;
pub const CMD_SET_REMOTE_MODE: u8 = 0xF0;
pub const CMD_GET_DEVICE_ID: u8 = 0xF2;
pub const CMD_SET_SAMPLE_RATE: u8 = 0xF3;
pub const CMD_ENABLE_REPORTING: u8 = 0xF4;
pub const CMD_DISABLE_REPORTING: u8 = 0xF5;
pub const CMD_SET_DEFAULTS: u8 = 0xF6;
pub const CMD_RESET: u8 = 0xFF;

pub const RESP_ACK: u8 = 0xFA;
pub const RESP_SELF_TEST_PASS: u8 = 0xAA;

pub const DEVICE_ID_STANDARD: u8 = 0x00;
pub const DEVICE_ID_WHEEL: u8 = 0x03;
pub const DEVICE_ID_5_BUTTON: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseType {
    Standard,
    Wheel,
    FiveButton,
}

impl MouseType {
    pub const fn packet_size(self) -> usize {
        match self {
            Self::Standard => 3,
            Self::Wheel | Self::FiveButton => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Count1PerMm = 0,
    Count2PerMm = 1,
    Count4PerMm = 2,
    Count8PerMm = 3,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MousePacket {
    pub buttons: MouseButtons,
    pub dx: i16,
    pub dy: i16,
    pub dz: i8,
}

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
        if !controller.port2_working() {
            return Err(Ps2Error::MouseNotDetected);
        }

        let response = controller.send_command(2, CMD_RESET)?;
        if response != RESP_ACK {
            return Err(Ps2Error::InvalidResponse);
        }

        let self_test = controller.read_data()?;
        if self_test != RESP_SELF_TEST_PASS {
            return Err(Ps2Error::SelfTestFailed);
        }

        let _ = controller.read_data();

        self.mouse_type = self.detect_type(controller)?;

        let _ = controller.send_command(2, CMD_SET_DEFAULTS);
        let _ = controller.send_command(2, CMD_ENABLE_REPORTING);

        self.detected = true;
        Ok(())
    }

    fn detect_type(&self, controller: &Controller) -> Ps2Result<MouseType> {
        self.set_sample_rate(controller, 200)?;
        self.set_sample_rate(controller, 100)?;
        self.set_sample_rate(controller, 80)?;

        let id = self.get_device_id(controller)?;
        if id == DEVICE_ID_WHEEL || id == DEVICE_ID_5_BUTTON {
            self.set_sample_rate(controller, 200)?;
            self.set_sample_rate(controller, 200)?;
            self.set_sample_rate(controller, 80)?;

            let id2 = self.get_device_id(controller)?;
            if id2 == DEVICE_ID_5_BUTTON {
                return Ok(MouseType::FiveButton);
            }
            return Ok(MouseType::Wheel);
        }

        Ok(MouseType::Standard)
    }

    fn set_sample_rate(&self, controller: &Controller, rate: u8) -> Ps2Result<()> {
        controller.write_port2(CMD_SET_SAMPLE_RATE)?;
        let _ = controller.read_data()?;
        controller.write_port2(rate)?;
        let _ = controller.read_data()?;
        Ok(())
    }

    fn get_device_id(&self, controller: &Controller) -> Ps2Result<u8> {
        controller.write_port2(CMD_GET_DEVICE_ID)?;
        let _ = controller.read_data()?;
        controller.read_data()
    }

    pub fn process_byte(&mut self, byte: u8) -> Option<MousePacket> {
        if self.packet_index == 0 && (byte & 0x08) == 0 {
            return None;
        }

        self.packet_buffer[self.packet_index] = byte;
        self.packet_index += 1;

        let packet_size = self.mouse_type.packet_size();
        if self.packet_index >= packet_size {
            self.packet_index = 0;
            return Some(self.parse_packet());
        }

        None
    }

    fn parse_packet(&self) -> MousePacket {
        let byte0 = self.packet_buffer[0];
        let byte1 = self.packet_buffer[1];
        let byte2 = self.packet_buffer[2];

        let mut buttons = MouseButtons::new();
        if byte0 & 0x01 != 0 {
            buttons.set(super::super::types::MouseButton::Left);
        }
        if byte0 & 0x02 != 0 {
            buttons.set(super::super::types::MouseButton::Right);
        }
        if byte0 & 0x04 != 0 {
            buttons.set(super::super::types::MouseButton::Middle);
        }

        let dx = if byte0 & 0x10 != 0 {
            byte1 as i16 | 0xFF00u16 as i16
        } else {
            byte1 as i16
        };

        let dy = if byte0 & 0x20 != 0 {
            -(byte2 as i16 | 0xFF00u16 as i16)
        } else {
            -(byte2 as i16)
        };

        let mut dz: i8 = 0;
        if self.mouse_type != MouseType::Standard {
            let byte3 = self.packet_buffer[3];
            dz = (byte3 & 0x0F) as i8;
            if byte3 & 0x08 != 0 {
                dz |= 0xF0u8 as i8;
            }

            if self.mouse_type == MouseType::FiveButton {
                if byte3 & 0x10 != 0 {
                    buttons.set(super::super::types::MouseButton::Button4);
                }
                if byte3 & 0x20 != 0 {
                    buttons.set(super::super::types::MouseButton::Button5);
                }
            }
        }

        MousePacket { buttons, dx, dy, dz }
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
