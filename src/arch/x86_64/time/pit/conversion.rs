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

use super::constants::{PIT_FREQUENCY, MAX_DIVISOR, MIN_DIVISOR, MAX_TIMER_FREQUENCY};
use super::types::{PitError, PitResult};

pub fn frequency_to_divisor(frequency_hz: u32) -> PitResult<u16> {
    if frequency_hz == 0 {
        return Err(PitError::InvalidFrequency);
    }

    if frequency_hz > MAX_TIMER_FREQUENCY {
        return Err(PitError::InvalidFrequency);
    }

    let divisor = PIT_FREQUENCY / frequency_hz as u64;

    if divisor > MAX_DIVISOR as u64 {
        return Err(PitError::InvalidFrequency);
    }

    if divisor < MIN_DIVISOR as u64 {
        return Err(PitError::InvalidFrequency);
    }

    Ok(divisor as u16)
}

pub fn divisor_to_frequency(divisor: u16) -> u32 {
    if divisor == 0 {
        return 0;
    }
    (PIT_FREQUENCY / divisor as u64) as u32
}

pub fn period_us_to_divisor(period_us: u32) -> PitResult<u16> {
    if period_us == 0 {
        return Err(PitError::InvalidDivisor);
    }

    let divisor = (period_us as u64 * PIT_FREQUENCY) / 1_000_000;

    if divisor > MAX_DIVISOR as u64 {
        return Err(PitError::InvalidDivisor);
    }

    if divisor < MIN_DIVISOR as u64 {
        return Err(PitError::InvalidDivisor);
    }

    Ok(divisor as u16)
}

pub fn divisor_to_period_ns(divisor: u16) -> u64 {
    if divisor == 0 {
        return 0;
    }
    (divisor as u64 * 1_000_000_000) / PIT_FREQUENCY
}

pub fn frequency_error(desired_hz: u32, divisor: u16) -> i32 {
    let actual = divisor_to_frequency(divisor);
    actual as i32 - desired_hz as i32
}
