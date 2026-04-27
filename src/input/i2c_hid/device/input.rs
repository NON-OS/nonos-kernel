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

use super::super::protocol::parse_input_report;
use super::super::touchpad::TouchpadState;
use super::types::{I2cHidDevice, I2cHidError};
use alloc::vec::Vec;

impl I2cHidDevice {
    pub fn poll_input(&mut self) -> Result<Option<(u8, Vec<u8>)>, I2cHidError> {
        if !self.initialized {
            return Err(I2cHidError::NotInitialized);
        }
        let reg = self.hid_desc.input_register.to_le_bytes();
        let max_len = self.hid_desc.max_input_length as usize;
        if self.input_buffer.len() < max_len {
            self.input_buffer.resize(max_len, 0);
        }
        crate::drivers::i2c::write_read(
            self.controller,
            self.address,
            &reg,
            &mut self.input_buffer[..max_len],
        )?;
        if let Some((report_id, data)) = parse_input_report(&self.input_buffer[..max_len]) {
            if data.iter().any(|&b| b != 0) {
                return Ok(Some((report_id, data.to_vec())));
            }
        }
        Ok(None)
    }

    pub fn poll_touchpad(&mut self) -> Result<Option<TouchpadState>, I2cHidError> {
        let input = self.poll_input()?;
        if let Some((report_id, data)) = input {
            if let Some(ref mut driver) = self.touchpad_driver {
                return Ok(driver.process_report(report_id, &data));
            }
        }
        Ok(None)
    }
}
