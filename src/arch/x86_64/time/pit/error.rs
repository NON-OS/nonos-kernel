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
pub enum PitError {
    NotInitialized = 0,
    AlreadyInitialized = 1,
    InvalidFrequency = 2,
    InvalidDivisor = 3,
    InvalidChannel = 4,
    InvalidMode = 5,
    ChannelBusy = 6,
    Timeout = 7,
    HardwareError = 8,
    CalibrationFailed = 9,
    SpeakerUnavailable = 10,
    OneShotPending = 11,
}

impl PitError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "PIT not initialized",
            Self::AlreadyInitialized => "PIT already initialized",
            Self::InvalidFrequency => "Invalid frequency requested",
            Self::InvalidDivisor => "Invalid divisor value",
            Self::InvalidChannel => "Invalid channel specified",
            Self::InvalidMode => "Invalid operating mode",
            Self::ChannelBusy => "Channel not available",
            Self::Timeout => "Timeout waiting for operation",
            Self::HardwareError => "Hardware access error",
            Self::CalibrationFailed => "Calibration failed",
            Self::SpeakerUnavailable => "Speaker not available",
            Self::OneShotPending => "One-shot timer already pending",
        }
    }
}

pub type PitResult<T> = Result<T, PitError>;
