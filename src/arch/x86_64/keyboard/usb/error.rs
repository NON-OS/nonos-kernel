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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHidError {
    NotInitialized,
    AlreadyInitialized,
    XhciInitFailed,
    UsbInitFailed,
    NoDevices,
    EnumerationFailed,
    PollFailed,
    InvalidReport,
    DeviceNotFound,
    EndpointNotFound,
    TransferFailed,
    RegistryFull,
    InvalidDeviceId,
    SetProtocolFailed,
    SetLedFailed,
    Timeout,
}

impl UsbHidError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "USB HID driver not initialized",
            Self::AlreadyInitialized => "USB HID driver already initialized",
            Self::XhciInitFailed => "xHCI controller initialization failed",
            Self::UsbInitFailed => "USB stack initialization failed",
            Self::NoDevices => "no USB HID devices found",
            Self::EnumerationFailed => "HID device enumeration failed",
            Self::PollFailed => "USB HID polling failed",
            Self::InvalidReport => "invalid HID report received",
            Self::DeviceNotFound => "USB HID device not found",
            Self::EndpointNotFound => "USB HID endpoint not found",
            Self::TransferFailed => "USB transfer failed",
            Self::RegistryFull => "USB HID device registry full",
            Self::InvalidDeviceId => "invalid USB HID device ID",
            Self::SetProtocolFailed => "failed to set HID protocol",
            Self::SetLedFailed => "failed to set keyboard LEDs",
            Self::Timeout => "USB HID operation timeout",
        }
    }

    pub const fn code(self) -> u8 {
        match self {
            Self::NotInitialized => 1,
            Self::AlreadyInitialized => 2,
            Self::XhciInitFailed => 3,
            Self::UsbInitFailed => 4,
            Self::NoDevices => 5,
            Self::EnumerationFailed => 6,
            Self::PollFailed => 7,
            Self::InvalidReport => 8,
            Self::DeviceNotFound => 9,
            Self::EndpointNotFound => 10,
            Self::TransferFailed => 11,
            Self::RegistryFull => 12,
            Self::InvalidDeviceId => 13,
            Self::SetProtocolFailed => 14,
            Self::SetLedFailed => 15,
            Self::Timeout => 16,
        }
    }
}

pub type UsbHidResult<T> = Result<T, UsbHidError>;
