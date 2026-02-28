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

use super::super::controller::Controller;
use super::super::super::error::{Ps2Error, Ps2Result};
use super::super::super::types::LedState;
use super::constants::*;
use super::typematic::{ScanCodeSet, TypematicConfig};

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
