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
#[repr(u8)]
pub enum CpuError {
    None = 0,
    NotInitialized = 1,
    AlreadyInitialized = 2,
    CpuidNotSupported = 3,
    InvalidCpuId = 4,
    InvalidMsr = 5,
    FeatureNotSupported = 6,
    CalibrationFailed = 7,
    TemperatureUnavailable = 8,
    PowerStateError = 9,
    NoCpuid = 10,
    NoLongMode = 11,
}

impl CpuError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::NotInitialized => "CPU detection not initialized",
            Self::AlreadyInitialized => "CPU detection already initialized",
            Self::CpuidNotSupported => "CPUID instruction not supported",
            Self::InvalidCpuId => "invalid CPU ID",
            Self::InvalidMsr => "invalid MSR address",
            Self::FeatureNotSupported => "feature not supported on this CPU",
            Self::CalibrationFailed => "frequency calibration failed",
            Self::TemperatureUnavailable => "temperature reading unavailable",
            Self::PowerStateError => "power state change failed",
            Self::NoCpuid => "CPUID instruction not available",
            Self::NoLongMode => "long mode (64-bit) not supported",
        }
    }
}
