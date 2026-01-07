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
pub enum WifiError {
    NotInitialized,
    DeviceNotFound,
    FirmwareNotFound,
    FirmwareInvalid,
    FirmwareLoadFailed,
    HardwareError,
    Timeout,
    InvalidState,
    NotConnected,
    AuthenticationFailed,
    AssociationFailed,
    ScanFailed,
    NoNetwork,
    InvalidParameter,
    BufferTooSmall,
    DmaError,
    CommandFailed,
    RfKill,
    NvmError,
    OutOfMemory,
}

impl WifiError {
    pub fn code(&self) -> u32 {
        match self {
            WifiError::NotInitialized => 0x0001,
            WifiError::DeviceNotFound => 0x0002,
            WifiError::FirmwareNotFound => 0x0003,
            WifiError::FirmwareInvalid => 0x0004,
            WifiError::FirmwareLoadFailed => 0x0005,
            WifiError::HardwareError => 0x0006,
            WifiError::Timeout => 0x0007,
            WifiError::InvalidState => 0x0008,
            WifiError::NotConnected => 0x0009,
            WifiError::AuthenticationFailed => 0x000A,
            WifiError::AssociationFailed => 0x000B,
            WifiError::ScanFailed => 0x000C,
            WifiError::NoNetwork => 0x000D,
            WifiError::InvalidParameter => 0x000E,
            WifiError::BufferTooSmall => 0x000F,
            WifiError::DmaError => 0x0010,
            WifiError::CommandFailed => 0x0011,
            WifiError::RfKill => 0x0012,
            WifiError::NvmError => 0x0013,
            WifiError::OutOfMemory => 0x0014,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WifiError::NotInitialized => "WiFi not initialized",
            WifiError::DeviceNotFound => "WiFi device not found",
            WifiError::FirmwareNotFound => "Firmware not found",
            WifiError::FirmwareInvalid => "Invalid firmware",
            WifiError::FirmwareLoadFailed => "Firmware load failed",
            WifiError::HardwareError => "Hardware error",
            WifiError::Timeout => "Operation timeout",
            WifiError::InvalidState => "Invalid state",
            WifiError::NotConnected => "Not connected",
            WifiError::AuthenticationFailed => "Authentication failed",
            WifiError::AssociationFailed => "Association failed",
            WifiError::ScanFailed => "Scan failed",
            WifiError::NoNetwork => "Network not found",
            WifiError::InvalidParameter => "Invalid parameter",
            WifiError::BufferTooSmall => "Buffer too small",
            WifiError::DmaError => "DMA error",
            WifiError::CommandFailed => "Command failed",
            WifiError::RfKill => "RF kill active",
            WifiError::NvmError => "NVM error",
            WifiError::OutOfMemory => "Out of memory",
        }
    }
}

impl core::fmt::Display for WifiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
