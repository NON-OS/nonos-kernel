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

use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::RwLock;
use super::constants::MAX_CPUS;
use super::types::{TscFeatures, TscCalibration, PerCpuTsc, CalibrationSource};

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CALIBRATED: AtomicBool = AtomicBool::new(false);

pub static FEATURES: RwLock<TscFeatures> = RwLock::new(TscFeatures {
    tsc_available: false, rdtscp_available: false, invariant_tsc: false,
    deadline_mode: false, cpuid_frequency: false, tsc_adjust: false, always_running: false,
});

pub static CALIBRATION: RwLock<TscCalibration> = RwLock::new(TscCalibration {
    frequency_hz: 0, boot_tsc: 0, source: CalibrationSource::None,
    confidence: 0, calibration_tsc: 0, samples: 0,
});

pub static PER_CPU_TSC: RwLock<[PerCpuTsc; MAX_CPUS]> = RwLock::new([const { PerCpuTsc {
    initialized: false, offset: 0, last_sync_tsc: 0, sync_error: 0,
} }; MAX_CPUS]);

pub static STATS_RDTSC_CALLS: AtomicU64 = AtomicU64::new(0);
pub static STATS_RDTSCP_CALLS: AtomicU64 = AtomicU64::new(0);
