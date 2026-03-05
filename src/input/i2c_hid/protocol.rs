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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HidCommand {
    Reset = 0x01,
    GetReport = 0x02,
    SetReport = 0x03,
    GetIdle = 0x04,
    SetIdle = 0x05,
    GetProtocol = 0x06,
    SetProtocol = 0x07,
    SetPower = 0x08,
}

impl HidCommand {
    pub fn opcode(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HidReportType {
    Feature = 0x03,
}

impl HidReportType {
    pub(crate) fn value(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HidPowerState {
    On = 0x00,
    Sleep = 0x01,
}

impl HidPowerState {
    pub(crate) fn value(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HidRegister {
    pub value: u16,
}

impl HidRegister {
    pub const HID_DESC: Self = Self { value: 0x0001 };

    pub fn new(value: u16) -> Self {
        Self { value }
    }

    pub fn to_le_bytes(&self) -> [u8; 2] {
        self.value.to_le_bytes()
    }
}

pub(super) fn build_reset_command(cmd_reg: u16) -> [u8; 4] {
    let cmd_bytes = cmd_reg.to_le_bytes();
    [
        cmd_bytes[0],
        cmd_bytes[1],
        HidCommand::Reset.opcode(),
        0x00,
    ]
}

pub(super) fn build_set_power_command(cmd_reg: u16, state: HidPowerState) -> [u8; 4] {
    let cmd_bytes = cmd_reg.to_le_bytes();
    [
        cmd_bytes[0],
        cmd_bytes[1],
        HidCommand::SetPower.opcode() | (state.value() << 4),
        0x00,
    ]
}

pub(crate) fn build_get_report_command(
    cmd_reg: u16,
    data_reg: u16,
    report_type: HidReportType,
    report_id: u8,
) -> [u8; 6] {
    let cmd_bytes = cmd_reg.to_le_bytes();
    let data_bytes = data_reg.to_le_bytes();

    let opcode = if report_id < 0x0F {
        (report_id << 4) | HidCommand::GetReport.opcode()
    } else {
        HidCommand::GetReport.opcode()
    };

    [
        cmd_bytes[0],
        cmd_bytes[1],
        opcode,
        report_type.value(),
        data_bytes[0],
        data_bytes[1],
    ]
}

pub(crate) fn build_set_report_command(
    cmd_reg: u16,
    data_reg: u16,
    report_type: HidReportType,
    report_id: u8,
    data: &[u8],
) -> alloc::vec::Vec<u8> {
    let cmd_bytes = cmd_reg.to_le_bytes();
    let data_bytes = data_reg.to_le_bytes();

    let opcode = if report_id < 0x0F {
        (report_id << 4) | HidCommand::SetReport.opcode()
    } else {
        HidCommand::SetReport.opcode()
    };

    let data_len = data.len() + 2;
    let len_bytes = (data_len as u16).to_le_bytes();

    let mut cmd = alloc::vec![
        cmd_bytes[0],
        cmd_bytes[1],
        opcode,
        report_type.value(),
        data_bytes[0],
        data_bytes[1],
        len_bytes[0],
        len_bytes[1],
        report_id,
    ];

    cmd.extend_from_slice(data);
    cmd
}

pub(crate) fn build_set_idle_command(cmd_reg: u16, report_id: u8, idle_rate: u8) -> [u8; 4] {
    let cmd_bytes = cmd_reg.to_le_bytes();
    [
        cmd_bytes[0],
        cmd_bytes[1],
        (report_id << 4) | HidCommand::SetIdle.opcode(),
        idle_rate,
    ]
}

pub(super) fn parse_input_report(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.len() < 3 {
        return None;
    }

    let length = u16::from_le_bytes([data[0], data[1]]) as usize;
    if length < 3 || length > data.len() {
        return None;
    }

    let report_id = data[2];
    let report_data = &data[3..length];

    Some((report_id, report_data))
}

pub(crate) const HID_USAGE_PAGE_DIGITIZER: u16 = 0x0D;
pub(crate) const HID_USAGE_PAGE_GENERIC_DESKTOP: u16 = 0x01;
pub(crate) const HID_USAGE_PAGE_BUTTON: u16 = 0x09;

pub(crate) const HID_USAGE_TOUCHPAD: u8 = 0x05;
pub(crate) const HID_USAGE_TOUCH_SCREEN: u8 = 0x04;
pub(crate) const HID_USAGE_MOUSE: u8 = 0x02;
pub(crate) const HID_USAGE_KEYBOARD: u8 = 0x06;

pub(crate) const HID_USAGE_TIP_SWITCH: u8 = 0x42;
pub(crate) const HID_USAGE_CONTACT_ID: u8 = 0x51;
pub(crate) const HID_USAGE_X: u8 = 0x30;
pub(crate) const HID_USAGE_Y: u8 = 0x31;
pub(crate) const HID_USAGE_CONTACT_COUNT: u8 = 0x54;
pub(crate) const HID_USAGE_BUTTON_PRIMARY: u8 = 0x01;
pub(crate) const HID_USAGE_BUTTON_SECONDARY: u8 = 0x02;

pub(crate) static SUPPORTED_COMMANDS: &[HidCommand] = &[
    HidCommand::Reset,
    HidCommand::GetReport,
    HidCommand::SetReport,
    HidCommand::GetIdle,
    HidCommand::SetIdle,
    HidCommand::GetProtocol,
    HidCommand::SetProtocol,
    HidCommand::SetPower,
];

pub(crate) fn register_address(reg: HidRegister) -> u16 {
    reg.value
}
