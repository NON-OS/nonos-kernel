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
pub enum RtcError {
    NotInitialized = 0,
    AlreadyInitialized = 1,
    InvalidTime = 2,
    InvalidDate = 3,
    InvalidAlarm = 4,
    UpdateInProgress = 5,
    BatteryFailure = 6,
    InvalidRegister = 7,
    InvalidChecksum = 8,
    HardwareError = 9,
    Timeout = 10,
    NoCenturyRegister = 11,
}

impl RtcError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "RTC not initialized",
            Self::AlreadyInitialized => "RTC already initialized",
            Self::InvalidTime => "Invalid time value",
            Self::InvalidDate => "Invalid date value",
            Self::InvalidAlarm => "Invalid alarm value",
            Self::UpdateInProgress => "Update in progress timeout",
            Self::BatteryFailure => "RTC battery failure",
            Self::InvalidRegister => "Invalid register address",
            Self::InvalidChecksum => "Invalid CMOS checksum",
            Self::HardwareError => "Hardware access error",
            Self::Timeout => "Timeout waiting for RTC",
            Self::NoCenturyRegister => "Century register not available",
        }
    }
}

pub type RtcResult<T> = Result<T, RtcError>;
