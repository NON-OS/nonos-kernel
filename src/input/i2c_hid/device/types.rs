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
use super::super::touchpad::TouchpadDriver;
use crate::drivers::i2c::I2cError;
use alloc::vec::Vec;

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
    pub(super) controller: usize,
    pub(super) address: u8,
    pub(super) hid_desc: HidDescriptor,
    pub(super) report_desc: ReportDescriptor,
    pub(super) device_type: HidDeviceType,
    pub(super) initialized: bool,
    pub(super) touchpad_driver: Option<TouchpadDriver>,
    pub(super) input_buffer: Vec<u8>,
}

impl I2cHidDevice {
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
        self.touchpad_driver.as_ref().map_or((0, 0), |d| (d.logical_max_x(), d.logical_max_y()))
    }
}
