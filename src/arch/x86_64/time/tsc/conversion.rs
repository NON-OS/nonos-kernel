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

use super::state::CALIBRATION;

#[inline]
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    let (result, overflow) = ticks.overflowing_mul(1_000_000_000);
    if overflow {
        (ticks / freq) * 1_000_000_000 + ((ticks % freq) * 1_000_000_000) / freq
    } else {
        result / freq
    }
}

#[inline]
pub fn ticks_to_us(ticks: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000_000) / freq
}

#[inline]
pub fn ticks_to_ms(ticks: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ticks * 1_000) / freq
}

#[inline]
pub fn ns_to_ticks(ns: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ns * freq) / 1_000_000_000
}

#[inline]
pub fn us_to_ticks(us: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (us * freq) / 1_000_000
}

#[inline]
pub fn ms_to_ticks(ms: u64) -> u64 {
    let freq = CALIBRATION.read().frequency_hz;
    if freq == 0 {
        return 0;
    }
    (ms * freq) / 1_000
}

pub fn tsc_to_ns(tsc_ticks: u64, tsc_freq: u64) -> u64 {
    if tsc_freq == 0 {
        return 0;
    }
    (tsc_ticks * 1_000_000_000) / tsc_freq
}

pub fn ns_to_tsc(nanoseconds: u64, tsc_freq: u64) -> u64 {
    if tsc_freq == 0 {
        return 0;
    }
    (nanoseconds * tsc_freq) / 1_000_000_000
}
