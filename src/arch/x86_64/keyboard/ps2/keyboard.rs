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
use super::super::types::LedState;

pub const CMD_SET_LEDS: u8 = 0xED;
pub const CMD_ECHO: u8 = 0xEE;
pub const CMD_GET_SET_SCANCODE: u8 = 0xF0;
pub const CMD_IDENTIFY: u8 = 0xF2;
pub const CMD_SET_TYPEMATIC: u8 = 0xF3;
pub const CMD_ENABLE_SCANNING: u8 = 0xF4;
pub const CMD_DISABLE_SCANNING: u8 = 0xF5;
pub const CMD_SET_DEFAULTS: u8 = 0xF6;
pub const CMD_RESEND: u8 = 0xFE;
pub const CMD_RESET: u8 = 0xFF;

pub const RESP_ACK: u8 = 0xFA;
pub const RESP_RESEND: u8 = 0xFE;
pub const RESP_ECHO: u8 = 0xEE;
pub const RESP_SELF_TEST_PASS: u8 = 0xAA;
pub const RESP_SELF_TEST_FAIL1: u8 = 0xFC;
pub const RESP_SELF_TEST_FAIL2: u8 = 0xFD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCodeSet {
    Set1 = 1,
    Set2 = 2,
    Set3 = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct TypematicConfig {
    pub delay_ms: u16,
    pub rate_hz: u8,
}

impl TypematicConfig {
    pub const fn default_config() -> Self {
        Self {
            delay_ms: 500,
            rate_hz: 10,
        }
    }

    pub fn to_byte(self) -> u8 {
        let delay = match self.delay_ms {
            0..=312 => 0,
            313..=562 => 1,
            563..=812 => 2,
            _ => 3,
        };

        let rate = match self.rate_hz {
            0..=2 => 0x1F,
            3..=4 => 0x14,
            5..=6 => 0x10,
            7..=9 => 0x0C,
            10..=12 => 0x0A,
            13..=16 => 0x08,
            17..=20 => 0x06,
            21..=24 => 0x04,
            25..=27 => 0x02,
            28..=30 => 0x01,
            _ => 0x00,
        };

        (delay << 5) | rate
    }
}

impl Default for TypematicConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

pub struct Keyboard {
    detected: bool,
    scancode_set: ScanCodeSet,
}

impl Keyboard {
    pub const fn new() -> Self {
        Self {
            detected: false,
            scancode_set: ScanCodeSet::Set1,
        }
    }

    pub fn init(&mut self, controller: &Controller) -> Ps2Result<()> {
        if !controller.port1_working() {
            return Err(Ps2Error::KeyboardNotDetected);
        }

        let response = controller.send_command(1, CMD_RESET)?;
        if response != RESP_ACK {
            return Err(Ps2Error::InvalidResponse);
        }

        let self_test = controller.read_data()?;
        if self_test != RESP_SELF_TEST_PASS {
            return Err(Ps2Error::SelfTestFailed);
        }

        let _ = controller.send_command(1, CMD_DISABLE_SCANNING);

        controller.write_data(CMD_GET_SET_SCANCODE)?;
        let _ = controller.read_data()?;
        controller.write_data(0)?;
        if let Ok(set) = controller.read_data() {
            self.scancode_set = match set {
                0x43 | 1 => ScanCodeSet::Set1,
                0x41 | 2 => ScanCodeSet::Set2,
                0x3F | 3 => ScanCodeSet::Set3,
                _ => ScanCodeSet::Set2,
            };
        }

        let _ = controller.send_command(1, CMD_ENABLE_SCANNING);

        self.detected = true;
        Ok(())
    }

    pub fn set_leds(&self, controller: &Controller, leds: LedState) -> Ps2Result<()> {
        if !self.detected {
            return Err(Ps2Error::KeyboardNotDetected);
        }

        let response = controller.send_command(1, CMD_SET_LEDS)?;
        if response != RESP_ACK {
            return Err(Ps2Error::InvalidResponse);
        }

        let response = controller.send_command(1, leds.bits())?;
        if response != RESP_ACK {
            return Err(Ps2Error::InvalidResponse);
        }

        Ok(())
    }

    pub fn set_typematic(&self, controller: &Controller, config: TypematicConfig) -> Ps2Result<()> {
        if !self.detected {
            return Err(Ps2Error::KeyboardNotDetected);
        }

        let response = controller.send_command(1, CMD_SET_TYPEMATIC)?;
        if response != RESP_ACK {
            return Err(Ps2Error::InvalidResponse);
        }

        let response = controller.send_command(1, config.to_byte())?;
        if response != RESP_ACK {
            return Err(Ps2Error::InvalidResponse);
        }

        Ok(())
    }

    pub const fn is_detected(&self) -> bool {
        self.detected
    }

    pub const fn scancode_set(&self) -> ScanCodeSet {
        self.scancode_set
    }
}

impl Default for Keyboard {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCodeState {
    Normal,
    Extended,
    ExtendedRelease,
    Pause(u8),
}

pub struct ScanCodeDecoder {
    state: ScanCodeState,
}

impl ScanCodeDecoder {
    pub const fn new() -> Self {
        Self {
            state: ScanCodeState::Normal,
        }
    }

    pub fn decode(&mut self, byte: u8) -> Option<(u8, bool, bool)> {
        match self.state {
            ScanCodeState::Normal => {
                match byte {
                    0xE0 => {
                        self.state = ScanCodeState::Extended;
                        None
                    }
                    0xE1 => {
                        self.state = ScanCodeState::Pause(0);
                        None
                    }
                    _ => {
                        let released = (byte & 0x80) != 0;
                        let code = byte & 0x7F;
                        Some((code, released, false))
                    }
                }
            }
            ScanCodeState::Extended => {
                let released = (byte & 0x80) != 0;
                let code = byte & 0x7F;
                self.state = ScanCodeState::Normal;
                Some((code, released, true))
            }
            ScanCodeState::ExtendedRelease => {
                self.state = ScanCodeState::Normal;
                Some((byte & 0x7F, true, true))
            }
            ScanCodeState::Pause(count) => {
                if count < 5 {
                    self.state = ScanCodeState::Pause(count + 1);
                    None
                } else {
                    self.state = ScanCodeState::Normal;
                    Some((0x45, false, true))
                }
            }
        }
    }

    pub fn reset(&mut self) {
        self.state = ScanCodeState::Normal;
    }
}

impl Default for ScanCodeDecoder {
    fn default() -> Self {
        Self::new()
    }
}
