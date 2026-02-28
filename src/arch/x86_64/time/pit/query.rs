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
use super::constants::{PIT_FREQUENCY, MAX_DIVISOR, MIN_DIVISOR, MAX_TIMER_FREQUENCY, MIN_TIMER_FREQUENCY};
use super::types::{Channel, Mode, PitStatistics};
use super::state::{INITIALIZED, CHANNELS, STATS_CALIBRATIONS, STATS_LAST_CALIBRATION, STATS_SPEAKER_BEEPS, STATS_ONESHOT_COMPLETED};
use super::io::{read_channel_count, read_channel_status};
use super::conversion::divisor_to_frequency;

pub fn get_channel_config(channel: Channel) -> Option<(Mode, u16, u32)> {
    let channels = CHANNELS.read();
    let ch = &channels[channel as usize];

    if ch.configured {
        Some((ch.mode, ch.divisor, ch.frequency_hz))
    } else {
        None
    }
}

pub fn read_count(channel: Channel) -> u16 {
    read_channel_count(channel)
}

pub fn read_status(channel: Channel) -> u8 {
    read_channel_status(channel)
}

pub fn is_output_high(channel: Channel) -> bool {
    let status = read_channel_status(channel);
    (status & 0x80) != 0
}

pub fn get_statistics() -> PitStatistics {
    let channels = CHANNELS.read();

    PitStatistics {
        initialized: INITIALIZED.load(Ordering::Relaxed),
        channel0_frequency: channels[0].frequency_hz,
        channel0_divisor: channels[0].divisor,
        channel0_ticks: channels[0].tick_count.load(Ordering::Relaxed),
        channel2_frequency: channels[2].frequency_hz,
        channel2_divisor: channels[2].divisor,
        calibrations: STATS_CALIBRATIONS.load(Ordering::Relaxed),
        last_calibration_hz: STATS_LAST_CALIBRATION.load(Ordering::Relaxed),
        speaker_beeps: STATS_SPEAKER_BEEPS.load(Ordering::Relaxed),
        oneshot_completed: STATS_ONESHOT_COMPLETED.load(Ordering::Relaxed),
    }
}

pub fn find_best_divisor(target_hz: u32) -> Option<(u16, u32, i32)> {
    if target_hz == 0 || target_hz > MAX_TIMER_FREQUENCY {
        return None;
    }

    let ideal_divisor = PIT_FREQUENCY / target_hz as u64;

    let candidates = [
        ideal_divisor.saturating_sub(1),
        ideal_divisor,
        ideal_divisor.saturating_add(1),
    ];

    let mut best_divisor = 0u16;
    let mut best_frequency = 0u32;
    let mut best_error = i32::MAX;

    for &div in &candidates {
        if div < MIN_DIVISOR as u64 || div > MAX_DIVISOR as u64 {
            continue;
        }

        let divisor = div as u16;
        let actual_freq = divisor_to_frequency(divisor);
        let error = (actual_freq as i32 - target_hz as i32).abs();

        if error < best_error {
            best_divisor = divisor;
            best_frequency = actual_freq;
            best_error = error;
        }
    }

    if best_divisor > 0 {
        Some((best_divisor, best_frequency, best_error))
    } else {
        None
    }
}

pub const fn max_frequency() -> u32 {
    MAX_TIMER_FREQUENCY
}

pub const fn min_frequency() -> u32 {
    MIN_TIMER_FREQUENCY
}

pub const fn oscillator_frequency() -> u64 {
    PIT_FREQUENCY
}
