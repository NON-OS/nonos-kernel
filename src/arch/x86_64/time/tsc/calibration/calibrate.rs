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

use core::sync::atomic::Ordering;
use super::super::constants::{CALIBRATION_SAMPLES, MIN_FREQUENCY, MAX_FREQUENCY};
use super::super::error::{TscError, TscResult};
use super::super::types::CalibrationSource;
use super::super::asm::rdtsc;
use super::super::state::{FEATURES, CALIBRATION, CALIBRATED};
use super::cpuid::get_cpuid_frequency;
use super::pit::calibrate_with_pit;
use super::hpet::calibrate_with_hpet;

pub fn calibrate() -> TscResult<()> {
    if !FEATURES.read().tsc_available {
        return Err(TscError::NotAvailable);
    }

    let boot_tsc = rdtsc();

    if let Some(freq) = get_cpuid_frequency() {
        let mut cal = CALIBRATION.write();
        cal.frequency_hz = freq;
        cal.boot_tsc = boot_tsc;
        cal.source = CalibrationSource::Cpuid;
        cal.confidence = 100;
        cal.calibration_tsc = rdtsc();
        cal.samples = 1;
        CALIBRATED.store(true, Ordering::SeqCst);
        return Ok(());
    }

    match calibrate_with_pit() {
        Ok((freq, confidence)) => {
            let mut cal = CALIBRATION.write();
            cal.frequency_hz = freq;
            cal.boot_tsc = boot_tsc;
            cal.source = CalibrationSource::Pit;
            cal.confidence = confidence;
            cal.calibration_tsc = rdtsc();
            cal.samples = CALIBRATION_SAMPLES as u8;
            CALIBRATED.store(true, Ordering::SeqCst);
            return Ok(());
        }
        Err(_) => {}
    }

    Err(TscError::CalibrationFailed)
}

pub fn calibrate_with_hpet_base(hpet_base: u64) -> TscResult<()> {
    if !FEATURES.read().tsc_available {
        return Err(TscError::NotAvailable);
    }

    let boot_tsc = rdtsc();

    match calibrate_with_hpet(hpet_base) {
        Ok((freq, confidence)) => {
            let mut cal = CALIBRATION.write();
            cal.frequency_hz = freq;
            cal.boot_tsc = boot_tsc;
            cal.source = CalibrationSource::Hpet;
            cal.confidence = confidence;
            cal.calibration_tsc = rdtsc();
            cal.samples = CALIBRATION_SAMPLES as u8;
            CALIBRATED.store(true, Ordering::SeqCst);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub fn set_frequency(freq_hz: u64) -> TscResult<()> {
    if freq_hz < MIN_FREQUENCY || freq_hz > MAX_FREQUENCY {
        return Err(TscError::InvalidFrequency);
    }

    let boot_tsc = rdtsc();

    let mut cal = CALIBRATION.write();
    cal.frequency_hz = freq_hz;
    cal.boot_tsc = boot_tsc;
    cal.source = CalibrationSource::KnownFrequency;
    cal.confidence = 100;
    cal.calibration_tsc = rdtsc();
    cal.samples = 1;

    CALIBRATED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn get_frequency() -> u64 {
    CALIBRATION.read().frequency_hz
}

pub fn get_frequency_mhz() -> u64 {
    CALIBRATION.read().frequency_hz / 1_000_000
}
