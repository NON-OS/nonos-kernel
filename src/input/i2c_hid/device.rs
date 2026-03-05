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

use super::descriptor::{HidDescriptor, ReportDescriptor};
use super::protocol::{
    build_reset_command, build_set_power_command, build_get_report_command, build_set_report_command,
    build_set_idle_command, parse_input_report, HidPowerState, HidReportType, HidRegister,
};
use super::touchpad::{TouchpadDriver, TouchpadState};
use alloc::vec;
use alloc::vec::Vec;
use crate::drivers::i2c::I2cError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDeviceType {
    Unknown,
    Touchpad,
    Mouse,
    Keyboard,
    Touchscreen,
}

#[derive(Debug)]
pub enum I2cHidError {
    I2c(I2cError),
    InvalidDescriptor,
    ResetFailed,
    NotInitialized,
    InvalidReport,
}

impl From<I2cError> for I2cHidError {
    fn from(e: I2cError) -> Self {
        I2cHidError::I2c(e)
    }
}

pub struct I2cHidDevice {
    controller: usize,
    address: u8,
    hid_desc: HidDescriptor,
    report_desc: ReportDescriptor,
    device_type: HidDeviceType,
    initialized: bool,
    touchpad_driver: Option<TouchpadDriver>,
    input_buffer: Vec<u8>,
}

impl I2cHidDevice {
    pub fn new(controller: usize, address: u8) -> Result<Self, I2cHidError> {
        let mut hid_desc_buf = [0u8; 30];

        let reg = HidRegister::HID_DESC.to_le_bytes();
        crate::drivers::i2c::write_read(controller, address, &reg, &mut hid_desc_buf)?;

        let hid_desc =
            HidDescriptor::parse(&hid_desc_buf).ok_or(I2cHidError::InvalidDescriptor)?;

        let max_input = hid_desc.max_input_length as usize;

        Ok(Self {
            controller,
            address,
            hid_desc,
            report_desc: ReportDescriptor::default(),
            device_type: HidDeviceType::Unknown,
            initialized: false,
            touchpad_driver: None,
            input_buffer: vec![0u8; max_input.max(64)],
        })
    }

    pub fn init(&mut self) -> Result<(), I2cHidError> {
        self.reset()?;

        self.fetch_report_descriptor()?;

        self.device_type = self.determine_device_type();

        if matches!(self.device_type, HidDeviceType::Touchpad | HidDeviceType::Mouse) {
            crate::log::info!(
                "i2c_hid: Touchpad VID:0x{:04X} PID:0x{:04X}",
                self.hid_desc.vendor_id,
                self.hid_desc.product_id
            );
            crate::log::info!(
                "i2c_hid: Logical max X:{} Y:{} contacts:{}",
                self.report_desc.logical_max_x,
                self.report_desc.logical_max_y,
                self.report_desc.max_contact_count
            );
            crate::log::info!(
                "i2c_hid: Input register:0x{:04X} max_len:{}",
                self.hid_desc.input_register,
                self.hid_desc.max_input_length
            );

            let driver = TouchpadDriver::new(
                self.report_desc.logical_max_x,
                self.report_desc.logical_max_y,
                self.report_desc.max_contact_count,
                self.report_desc.touchpad_layout.clone(),
            );

            self.touchpad_driver = Some(driver);

            let _ = self.set_idle(0, 0);
        }

        self.set_power(HidPowerState::On)?;

        self.initialized = true;

        Ok(())
    }

    fn reset(&mut self) -> Result<(), I2cHidError> {
        let cmd = build_reset_command(self.hid_desc.command_register);
        crate::drivers::i2c::write(self.controller, self.address, cmd[0], &cmd[1..])?;

        for _ in 0..100 {
            let mut reset_resp = [0u8; 2];
            if crate::drivers::i2c::read(self.controller, self.address, 0x00, &mut reset_resp)
                .is_ok()
            {
                if reset_resp[0] == 0 && reset_resp[1] == 0 {
                    return Ok(());
                }
            }
            spin_wait(1000);
        }

        Err(I2cHidError::ResetFailed)
    }

    fn set_power(&mut self, state: HidPowerState) -> Result<(), I2cHidError> {
        let cmd = build_set_power_command(self.hid_desc.command_register, state);
        crate::drivers::i2c::write(self.controller, self.address, cmd[0], &cmd[1..])?;
        spin_wait(100);
        Ok(())
    }

    fn fetch_report_descriptor(&mut self) -> Result<(), I2cHidError> {
        let len = self.hid_desc.report_descriptor_length as usize;
        if len == 0 || len > 4096 {
            return Err(I2cHidError::InvalidDescriptor);
        }

        let mut desc_buf = vec![0u8; len];
        let reg = self.hid_desc.report_descriptor_register.to_le_bytes();

        crate::drivers::i2c::write_read(self.controller, self.address, &reg, &mut desc_buf)?;

        self.report_desc = ReportDescriptor::parse(&desc_buf);

        Ok(())
    }

    fn determine_device_type(&self) -> HidDeviceType {
        if self.report_desc.is_touchpad() {
            return HidDeviceType::Touchpad;
        }
        if self.report_desc.is_mouse() {
            return HidDeviceType::Mouse;
        }
        if self.report_desc.has_keyboard {
            return HidDeviceType::Keyboard;
        }

        const TOUCHPAD_ADDRESSES: &[u8] = &[0x15, 0x2C, 0x10, 0x20, 0x38, 0x4B];
        if TOUCHPAD_ADDRESSES.contains(&self.address) {
            if self.report_desc.has_x && self.report_desc.has_y {
                return HidDeviceType::Touchpad;
            }
            return HidDeviceType::Touchpad;
        }

        HidDeviceType::Unknown
    }

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

    pub fn device_type(&self) -> HidDeviceType {
        self.device_type
    }

    pub fn hid_descriptor(&self) -> &HidDescriptor {
        &self.hid_desc
    }

    pub fn report_descriptor(&self) -> &ReportDescriptor {
        &self.report_desc
    }

    pub fn controller(&self) -> usize {
        self.controller
    }

    pub fn address(&self) -> u8 {
        self.address
    }

    pub fn is_using_layout(&self) -> bool {
        self.touchpad_driver.as_ref().map_or(false, |d| d.is_using_layout())
    }

    pub fn touchpad_logical_max(&self) -> (i32, i32) {
        self.touchpad_driver
            .as_ref()
            .map_or((0, 0), |d| (d.logical_max_x(), d.logical_max_y()))
    }

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

fn spin_wait(us: u64) {
    let start = crate::arch::x86_64::time::tsc::elapsed_us();
    while crate::arch::x86_64::time::tsc::elapsed_us() - start < us {
        core::hint::spin_loop();
    }
}
