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
use super::{ports, system_control};
use super::constants::{MAX_DIVISOR, MIN_TIMER_FREQUENCY};
use super::types::{PitError, PitResult, Channel, Mode};
use super::state::{STATS_CALIBRATIONS, STATS_LAST_CALIBRATION};
use super::io::{inb, outb, configure_channel_raw};
use super::conversion::{frequency_to_divisor, divisor_to_period_ns};
use super::speaker::get_channel2_output;

#[inline]
fn rdtsc() -> u64 {
    let hi: u32;
    let lo: u32;
    // SAFETY: rdtsc instruction reads timestamp counter, lfence ensures serialization.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

pub fn calibrate_tsc() -> PitResult<u64> {
    calibrate_tsc_with_duration(50)
}

pub fn calibrate_tsc_with_duration(duration_ms: u32) -> PitResult<u64> {
    let frequency_hz = 1000 / duration_ms.max(1);
    let divisor = if frequency_hz < MIN_TIMER_FREQUENCY {
        MAX_DIVISOR
    } else {
        frequency_to_divisor(frequency_hz)?
    };

    let period_ns = divisor_to_period_ns(divisor);

    // SAFETY: Accessing PIT and system control ports for TSC calibration.
    unsafe {
        let saved_control = inb(ports::SYSTEM_CONTROL_B);

        configure_channel_raw(Channel::Channel2, Mode::InterruptOnTerminal, divisor);

        outb(
            ports::SYSTEM_CONTROL_B,
            (saved_control & !system_control::SPEAKER_ENABLE) | system_control::TIMER2_GATE,
        );

        let mut timeout = 100_000u32;
        while !get_channel2_output() && timeout > 0 {
            timeout -= 1;
        }

        let start_tsc = rdtsc();

        timeout = 100_000_000;
        while get_channel2_output() && timeout > 0 {
            timeout -= 1;
            core::hint::spin_loop();
        }

        let end_tsc = rdtsc();

        outb(ports::SYSTEM_CONTROL_B, saved_control);

        if timeout == 0 {
            return Err(PitError::CalibrationFailed);
        }

        let tsc_ticks = end_tsc.saturating_sub(start_tsc);
        if tsc_ticks == 0 || period_ns == 0 {
            return Err(PitError::CalibrationFailed);
        }

        let frequency = (tsc_ticks * 1_000_000_000) / period_ns;

        STATS_CALIBRATIONS.fetch_add(1, Ordering::Relaxed);
        STATS_LAST_CALIBRATION.store(frequency, Ordering::Relaxed);

        Ok(frequency)
    }
}

pub fn calibrate_tsc_accurate() -> PitResult<u64> {
    const NUM_SAMPLES: usize = 5;
    let mut samples = [0u64; NUM_SAMPLES];
    let mut valid = 0;

    for sample in samples.iter_mut() {
        if let Ok(freq) = calibrate_tsc_with_duration(20) {
            *sample = freq;
            valid += 1;
        }
    }

    if valid < 3 {
        return Err(PitError::CalibrationFailed);
    }

    samples[..valid].sort_unstable();
    Ok(samples[valid / 2])
}
