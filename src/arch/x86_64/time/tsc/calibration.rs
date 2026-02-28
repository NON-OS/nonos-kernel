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
use super::constants::{DEFAULT_CALIBRATION_MS, CALIBRATION_SAMPLES, MIN_FREQUENCY, MAX_FREQUENCY};
use super::error::{TscError, TscResult};
use super::types::CalibrationSource;
use super::asm::{cpuid, cpuid_max_leaf, rdtsc, rdtsc_unserialized, inb, outb};
use super::state::{FEATURES, CALIBRATION, CALIBRATED};

pub fn get_cpuid_frequency() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x15 {
        return None;
    }

    let (eax, ebx, ecx, _) = cpuid(0x15, 0);

    if eax == 0 || ebx == 0 {
        return None;
    }

    let crystal_freq = if ecx != 0 {
        ecx as u64
    } else {
        if max_leaf >= 0x16 {
            let (base_mhz, _, _, _) = cpuid(0x16, 0);
            if base_mhz != 0 {
                return None;
            }
        }
        return None;
    };

    let tsc_freq = (crystal_freq * ebx as u64) / eax as u64;

    if tsc_freq >= MIN_FREQUENCY && tsc_freq <= MAX_FREQUENCY {
        Some(tsc_freq)
    } else {
        None
    }
}

pub fn calibrate_with_pit() -> TscResult<(u64, u8)> {
    const PIT_FREQUENCY: u64 = 1193182;
    const CALIBRATION_MS: u64 = DEFAULT_CALIBRATION_MS as u64;
    let pit_ticks = ((PIT_FREQUENCY * CALIBRATION_MS) / 1000) as u16;

    let mut samples = [0u64; CALIBRATION_SAMPLES];
    let mut valid_samples = 0;

    for sample in samples.iter_mut() {
        // SAFETY: PIT I/O ports are standard x86 hardware.
        unsafe {
            let speaker_port = inb(0x61);

            outb(0x43, 0xB0);
            outb(0x42, (pit_ticks & 0xFF) as u8);
            outb(0x42, ((pit_ticks >> 8) & 0xFF) as u8);

            outb(0x61, (speaker_port & 0xFC) | 0x01);

            let mut timeout = 100_000u32;
            while (inb(0x61) & 0x20) != 0 && timeout > 0 {
                timeout -= 1;
            }

            let start_tsc = rdtsc_unserialized();

            timeout = 100_000_000;
            while (inb(0x61) & 0x20) == 0 && timeout > 0 {
                timeout -= 1;
                core::hint::spin_loop();
            }

            let end_tsc = rdtsc_unserialized();

            outb(0x61, speaker_port);

            if timeout > 0 {
                let tsc_ticks = end_tsc.saturating_sub(start_tsc);
                let freq = (tsc_ticks * PIT_FREQUENCY) / pit_ticks as u64;
                if freq >= MIN_FREQUENCY && freq <= MAX_FREQUENCY {
                    *sample = freq;
                    valid_samples += 1;
                }
            }
        }
    }

    if valid_samples < 3 {
        return Err(TscError::CalibrationFailed);
    }

    samples[..valid_samples].sort_unstable();
    let median = samples[valid_samples / 2];

    let mut variance: u64 = 0;
    for &sample in &samples[..valid_samples] {
        let diff = if sample > median { sample - median } else { median - sample };
        variance += diff;
    }
    variance /= valid_samples as u64;

    let variance_pct = (variance * 100) / median;
    let confidence = if variance_pct == 0 {
        95
    } else if variance_pct < 1 {
        90
    } else if variance_pct < 5 {
        75
    } else {
        50
    };

    Ok((median, confidence))
}

pub fn calibrate_with_hpet(hpet_base: u64) -> TscResult<(u64, u8)> {
    const CALIBRATION_NS: u64 = DEFAULT_CALIBRATION_MS as u64 * 1_000_000;

    // SAFETY: HPET memory-mapped I/O access. Caller must provide valid base.
    unsafe {
        let capabilities = core::ptr::read_volatile(hpet_base as *const u64);
        let period_fs = (capabilities >> 32) as u32;

        if period_fs == 0 || period_fs > 100_000_000 {
            return Err(TscError::NoReferenceTimer);
        }

        let hpet_ticks_needed = (CALIBRATION_NS * 1_000_000) / period_fs as u64;

        let mut samples = [0u64; CALIBRATION_SAMPLES];
        let mut valid_samples = 0;

        let counter_reg = (hpet_base + 0xF0) as *const u64;

        for sample in samples.iter_mut() {
            let start_hpet = core::ptr::read_volatile(counter_reg);
            let start_tsc = rdtsc_unserialized();

            let end_hpet = start_hpet.wrapping_add(hpet_ticks_needed);
            let mut timeout = 100_000_000u32;
            while core::ptr::read_volatile(counter_reg) < end_hpet && timeout > 0 {
                timeout -= 1;
                core::hint::spin_loop();
            }

            if timeout == 0 {
                continue;
            }

            let end_tsc = rdtsc_unserialized();
            let actual_hpet = core::ptr::read_volatile(counter_reg);

            let elapsed_hpet = actual_hpet.saturating_sub(start_hpet);
            let elapsed_ns = (elapsed_hpet * period_fs as u64) / 1_000_000;

            if elapsed_ns > 0 {
                let tsc_ticks = end_tsc.saturating_sub(start_tsc);
                let freq = (tsc_ticks * 1_000_000_000) / elapsed_ns;

                if freq >= MIN_FREQUENCY && freq <= MAX_FREQUENCY {
                    *sample = freq;
                    valid_samples += 1;
                }
            }
        }

        if valid_samples < 3 {
            return Err(TscError::CalibrationFailed);
        }

        samples[..valid_samples].sort_unstable();
        let median = samples[valid_samples / 2];

        let confidence = 98;

        Ok((median, confidence))
    }
}

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
