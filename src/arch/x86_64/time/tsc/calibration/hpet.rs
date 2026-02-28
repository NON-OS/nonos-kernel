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
use super::super::asm::rdtsc_unserialized;

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
