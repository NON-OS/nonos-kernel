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

use super::conversion::ticks_to_ns;
use super::globals::{
    CALIBRATED, CALIBRATION, FEATURES, INITIALIZED, PER_CPU_TSC, STATS_RDTSCP_CALLS,
    STATS_RDTSC_CALLS,
};
use super::rdtsc::rdtsc;
use super::types::{CalibrationSource, TscStatistics};
use core::sync::atomic::Ordering;

pub fn is_calibrated() -> bool {
    CALIBRATED.load(Ordering::Relaxed)
}

pub fn get_statistics() -> TscStatistics {
    let features = *FEATURES.read();
    let cal = CALIBRATION.read();
    let initialized_cpus = PER_CPU_TSC.read().iter().filter(|c| c.initialized).count() as u32;
    let current_tsc = rdtsc();
    let uptime_ns = if cal.frequency_hz > 0 {
        ticks_to_ns(current_tsc.saturating_sub(cal.boot_tsc))
    } else {
        0
    };
    TscStatistics {
        features,
        initialized: INITIALIZED.load(Ordering::Relaxed),
        calibrated: CALIBRATED.load(Ordering::Relaxed),
        frequency_hz: cal.frequency_hz,
        calibration_source: cal.source,
        confidence: cal.confidence,
        boot_tsc: cal.boot_tsc,
        current_tsc,
        uptime_ns,
        calibration_samples: cal.samples,
        initialized_cpus,
        rdtsc_calls: STATS_RDTSC_CALLS.load(Ordering::Relaxed),
        rdtscp_calls: STATS_RDTSCP_CALLS.load(Ordering::Relaxed),
    }
}

pub fn get_calibration_source() -> CalibrationSource {
    CALIBRATION.read().source
}

pub fn get_confidence() -> u8 {
    CALIBRATION.read().confidence
}
