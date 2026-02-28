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

#[derive(Debug, Clone, Copy, Default)]
pub struct TscFeatures {
    pub tsc_available: bool,
    pub rdtscp_available: bool,
    pub invariant_tsc: bool,
    pub deadline_mode: bool,
    pub cpuid_frequency: bool,
    pub tsc_adjust: bool,
    pub always_running: bool,
}

impl TscFeatures {
    pub const fn is_reliable(&self) -> bool {
        self.tsc_available && self.invariant_tsc
    }

    pub const fn is_available(&self) -> bool {
        self.tsc_available
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CalibrationSource {
    #[default]
    None = 0,
    Cpuid = 1,
    Hpet = 2,
    Pit = 3,
    KnownFrequency = 4,
    CrossCalibration = 5,
}

impl CalibrationSource {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Cpuid => "CPUID.15H",
            Self::Hpet => "HPET",
            Self::Pit => "PIT",
            Self::KnownFrequency => "Known Frequency",
            Self::CrossCalibration => "Cross-Calibration",
        }
    }

    pub const fn accuracy_rating(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Pit => 2,
            Self::Hpet => 3,
            Self::KnownFrequency => 4,
            Self::CrossCalibration => 3,
            Self::Cpuid => 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TscCalibration {
    pub frequency_hz: u64,
    pub boot_tsc: u64,
    pub source: CalibrationSource,
    pub confidence: u8,
    pub calibration_tsc: u64,
    pub samples: u8,
}

impl Default for TscCalibration {
    fn default() -> Self {
        Self {
            frequency_hz: 0,
            boot_tsc: 0,
            source: CalibrationSource::None,
            confidence: 0,
            calibration_tsc: 0,
            samples: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PerCpuTsc {
    pub initialized: bool,
    pub offset: i64,
    pub last_sync_tsc: u64,
    pub sync_error: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TscStatistics {
    pub features: TscFeatures,
    pub initialized: bool,
    pub calibrated: bool,
    pub frequency_hz: u64,
    pub calibration_source: CalibrationSource,
    pub confidence: u8,
    pub boot_tsc: u64,
    pub current_tsc: u64,
    pub uptime_ns: u64,
    pub calibration_samples: u8,
    pub initialized_cpus: u32,
    pub rdtsc_calls: u64,
    pub rdtscp_calls: u64,
}
