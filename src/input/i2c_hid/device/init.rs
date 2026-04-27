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

use super::super::descriptor::{HidDescriptor, ReportDescriptor};
use super::super::protocol::{
    build_reset_command, build_set_power_command, HidPowerState, HidRegister,
};
use super::super::touchpad::TouchpadDriver;
use super::types::{HidDeviceType, I2cHidDevice, I2cHidError};
use super::utils::spin_wait;
use alloc::vec;

impl I2cHidDevice {
    pub fn new(controller: usize, address: u8) -> Result<Self, I2cHidError> {
        let mut hid_desc_buf = [0u8; 30];
        crate::drivers::i2c::write_read(
            controller,
            address,
            &HidRegister::HID_DESC.to_le_bytes(),
            &mut hid_desc_buf,
        )?;
        let hid_desc = HidDescriptor::parse(&hid_desc_buf).ok_or(I2cHidError::InvalidDescriptor)?;
        let buf_size = (hid_desc.max_input_length as usize).max(64);
        Ok(Self {
            controller,
            address,
            hid_desc,
            report_desc: ReportDescriptor::default(),
            device_type: HidDeviceType::Unknown,
            initialized: false,
            touchpad_driver: None,
            input_buffer: vec![0u8; buf_size],
        })
    }

    pub fn init(&mut self) -> Result<(), I2cHidError> {
        self.reset()?;
        self.fetch_report_descriptor()?;
        self.device_type = self.determine_device_type();
        if matches!(self.device_type, HidDeviceType::Touchpad | HidDeviceType::Mouse) {
            crate::log::info!(
                "i2c_hid: VID:0x{:04X} PID:0x{:04X} X:{} Y:{} contacts:{}",
                self.hid_desc.vendor_id,
                self.hid_desc.product_id,
                self.report_desc.logical_max_x,
                self.report_desc.logical_max_y,
                self.report_desc.max_contact_count
            );
            self.touchpad_driver = Some(TouchpadDriver::new(
                self.report_desc.logical_max_x,
                self.report_desc.logical_max_y,
                self.report_desc.max_contact_count,
                self.report_desc.touchpad_layout.clone(),
            ));
            let _ = self.set_idle(0, 0);
        }
        self.set_power(HidPowerState::On)?;
        self.initialized = true;
        Ok(())
    }

    pub(super) fn reset(&mut self) -> Result<(), I2cHidError> {
        let cmd = build_reset_command(self.hid_desc.command_register);
        crate::drivers::i2c::write(self.controller, self.address, cmd[0], &cmd[1..])?;
        for _ in 0..100 {
            let mut r = [0u8; 2];
            if crate::drivers::i2c::read(self.controller, self.address, 0x00, &mut r).is_ok()
                && r == [0, 0]
            {
                return Ok(());
            }
            spin_wait(1000);
        }
        Err(I2cHidError::ResetFailed)
    }

    pub(super) fn set_power(&mut self, state: HidPowerState) -> Result<(), I2cHidError> {
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
        crate::drivers::i2c::write_read(
            self.controller,
            self.address,
            &self.hid_desc.report_descriptor_register.to_le_bytes(),
            &mut desc_buf,
        )?;
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
        const TP_ADDRS: &[u8] = &[0x15, 0x2C, 0x10, 0x20, 0x38, 0x4B];
        if TP_ADDRS.contains(&self.address) {
            return HidDeviceType::Touchpad;
        }
        HidDeviceType::Unknown
    }
}
