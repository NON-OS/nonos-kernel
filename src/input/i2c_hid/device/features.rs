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

use super::super::protocol::{
    build_get_report_command, build_set_idle_command, build_set_report_command, HidPowerState,
    HidReportType,
};
use super::types::{I2cHidDevice, I2cHidError};
use super::utils::spin_wait;
use alloc::vec;
use alloc::vec::Vec;

impl I2cHidDevice {
    pub fn sleep(&mut self) -> Result<(), I2cHidError> {
        self.set_power(HidPowerState::Sleep)
    }
    pub fn wake(&mut self) -> Result<(), I2cHidError> {
        self.set_power(HidPowerState::On)
    }

    pub fn get_feature_report(&mut self, report_id: u8) -> Result<Vec<u8>, I2cHidError> {
        let cmd = build_get_report_command(
            self.hid_desc.command_register,
            self.hid_desc.data_register,
            HidReportType::Feature,
            report_id,
        );
        crate::drivers::i2c::write(self.controller, self.address, cmd[0], &cmd[1..])?;
        spin_wait(100);
        let mut response = vec![0u8; 64];
        let reg = self.hid_desc.data_register.to_le_bytes();
        crate::drivers::i2c::write_read(self.controller, self.address, &reg, &mut response)?;
        Ok(response)
    }

    pub fn set_feature_report(&mut self, report_id: u8, data: &[u8]) -> Result<(), I2cHidError> {
        let cmd = build_set_report_command(
            self.hid_desc.command_register,
            self.hid_desc.data_register,
            HidReportType::Feature,
            report_id,
            data,
        );
        crate::drivers::i2c::write(self.controller, self.address, cmd[0], &cmd[1..])?;
        spin_wait(100);
        Ok(())
    }

    pub fn set_idle(&mut self, report_id: u8, idle_rate: u8) -> Result<(), I2cHidError> {
        let cmd = build_set_idle_command(self.hid_desc.command_register, report_id, idle_rate);
        crate::drivers::i2c::write(self.controller, self.address, cmd[0], &cmd[1..])?;
        spin_wait(100);
        Ok(())
    }
}
