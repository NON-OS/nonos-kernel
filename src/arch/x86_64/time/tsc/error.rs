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
pub enum TscError {
    NotAvailable = 0,
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotCalibrated = 3,
    CalibrationFailed = 4,
    InvalidFrequency = 5,
    NotInvariant = 6,
    RdtscpUnavailable = 7,
    DeadlineModeUnavailable = 8,
    PerCpuNotInit = 9,
    Overflow = 10,
    CpuidUnavailable = 11,
    NoReferenceTimer = 12,
}

impl TscError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotAvailable => "TSC not available",
            Self::NotInitialized => "TSC not initialized",
            Self::AlreadyInitialized => "TSC already initialized",
            Self::NotCalibrated => "TSC not calibrated",
            Self::CalibrationFailed => "TSC calibration failed",
            Self::InvalidFrequency => "Invalid TSC frequency",
            Self::NotInvariant => "TSC not invariant (unstable across P-states)",
            Self::RdtscpUnavailable => "RDTSCP instruction not available",
            Self::DeadlineModeUnavailable => "TSC deadline mode not supported",
            Self::PerCpuNotInit => "Per-CPU TSC not initialized",
            Self::Overflow => "Overflow in time calculation",
            Self::CpuidUnavailable => "CPUID not available",
            Self::NoReferenceTimer => "No reference timer for calibration",
        }
    }
}

pub type TscResult<T> = Result<T, TscError>;
