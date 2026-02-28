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

use core::sync::atomic::{AtomicU64, Ordering};
use super::types::{PitError, PitResult, Channel, Mode};
use super::state::CHANNELS;
use super::io::configure_channel_raw;
use super::conversion::{frequency_to_divisor, divisor_to_frequency, divisor_to_period_ns};

pub fn init_system_timer(frequency_hz: u32) -> PitResult<()> {
    let divisor = frequency_to_divisor(frequency_hz)?;
    init_system_timer_with_divisor(divisor)
}

pub fn init_system_timer_with_divisor(divisor: u16) -> PitResult<()> {
    if divisor == 0 {
        return Err(PitError::InvalidDivisor);
    }

    configure_channel_raw(Channel::Channel0, Mode::RateGenerator, divisor);

    let frequency = divisor_to_frequency(divisor);

    {
        let mut channels = CHANNELS.write();
        channels[0].configured = true;
        channels[0].mode = Mode::RateGenerator;
        channels[0].divisor = divisor;
        channels[0].frequency_hz = frequency;
        channels[0].tick_count = AtomicU64::new(0);
    }

    Ok(())
}

pub fn system_timer_tick() {
    let channels = CHANNELS.read();
    channels[0].tick_count.fetch_add(1, Ordering::Relaxed);
}

pub fn get_system_timer_ticks() -> u64 {
    CHANNELS.read()[0].tick_count.load(Ordering::Relaxed)
}

pub fn get_system_timer_frequency() -> u32 {
    CHANNELS.read()[0].frequency_hz
}

pub fn elapsed_ns() -> u64 {
    let channels = CHANNELS.read();
    let ticks = channels[0].tick_count.load(Ordering::Relaxed);
    let divisor = channels[0].divisor;

    if divisor == 0 {
        return 0;
    }

    ticks * divisor_to_period_ns(divisor)
}

pub fn elapsed_ms() -> u64 {
    elapsed_ns() / 1_000_000
}
