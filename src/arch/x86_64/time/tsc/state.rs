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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use super::constants::MAX_CPUS;
use super::error::{TscError, TscResult};
use super::types::{TscFeatures, TscCalibration, PerCpuTsc, CalibrationSource, TscStatistics};
use super::asm::rdtsc;
use super::features::detect_features;
use super::calibration::{calibrate, calibrate_with_hpet_base};
use super::conversion::ticks_to_ns;
use super::per_cpu::init_cpu;

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub static CALIBRATED: AtomicBool = AtomicBool::new(false);

pub static FEATURES: RwLock<TscFeatures> = RwLock::new(TscFeatures {
    tsc_available: false,
    rdtscp_available: false,
    invariant_tsc: false,
    deadline_mode: false,
    cpuid_frequency: false,
    tsc_adjust: false,
    always_running: false,
});

pub static CALIBRATION: RwLock<TscCalibration> = RwLock::new(TscCalibration {
    frequency_hz: 0,
    boot_tsc: 0,
    source: CalibrationSource::None,
    confidence: 0,
    calibration_tsc: 0,
    samples: 0,
});

pub static PER_CPU_TSC: RwLock<[PerCpuTsc; MAX_CPUS]> = RwLock::new([const { PerCpuTsc {
    initialized: false,
    offset: 0,
    last_sync_tsc: 0,
    sync_error: 0,
} }; MAX_CPUS]);

pub static STATS_RDTSC_CALLS: AtomicU64 = AtomicU64::new(0);
pub static STATS_RDTSCP_CALLS: AtomicU64 = AtomicU64::new(0);

pub fn init() -> TscResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TscError::AlreadyInitialized);
    }

    let features = detect_features();
    *FEATURES.write() = features;

    if !features.tsc_available {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(TscError::NotAvailable);
    }

    calibrate()?;

    init_cpu(0)?;

    Ok(())
}

pub fn init_with_hpet(hpet_base: u64) -> TscResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(TscError::AlreadyInitialized);
    }

    let features = detect_features();
    *FEATURES.write() = features;

    if !features.tsc_available {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(TscError::NotAvailable);
    }

    calibrate_with_hpet_base(hpet_base)?;

    init_cpu(0)?;

    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

pub fn is_calibrated() -> bool {
    CALIBRATED.load(Ordering::Relaxed)
}

pub fn get_statistics() -> TscStatistics {
    let features = *FEATURES.read();
    let cal = CALIBRATION.read();

    let per_cpu = PER_CPU_TSC.read();
    let initialized_cpus = per_cpu.iter().filter(|c| c.initialized).count() as u32;

    let current_tsc = rdtsc();
    let uptime_ns = if cal.frequency_hz > 0 {
        let elapsed = current_tsc.saturating_sub(cal.boot_tsc);
        ticks_to_ns(elapsed)
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
