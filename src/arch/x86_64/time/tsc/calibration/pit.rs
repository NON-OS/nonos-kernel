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

use super::super::constants::{DEFAULT_CALIBRATION_MS, CALIBRATION_SAMPLES, MIN_FREQUENCY, MAX_FREQUENCY};
use super::super::error::{TscError, TscResult};
use super::super::asm::{rdtsc_unserialized, inb, outb};

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
