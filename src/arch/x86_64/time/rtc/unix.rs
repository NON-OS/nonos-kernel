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

use super::calendar::{day_of_week, days_in_month, is_leap_year};
use super::constants::{SECS_PER_DAY, SECS_PER_HOUR, SECS_PER_MIN, UNIX_EPOCH_YEAR};
use super::types::RtcTime;

pub fn datetime_to_unix(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u64 {
    let mut days = 0u64;
    for y in UNIX_EPOCH_YEAR..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += days_in_month(year, m) as u64;
    }
    days += (day - 1) as u64;
    days * SECS_PER_DAY
        + (hour as u64) * SECS_PER_HOUR
        + (minute as u64) * SECS_PER_MIN
        + second as u64
}

pub fn unix_to_datetime(timestamp: u64) -> RtcTime {
    let mut remaining = timestamp;
    let second = (remaining % 60) as u8;
    remaining /= 60;
    let minute = (remaining % 60) as u8;
    remaining /= 60;
    let hour = (remaining % 24) as u8;
    remaining /= 24;
    let mut year = UNIX_EPOCH_YEAR;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year as u64 {
            break;
        }
        remaining -= days_in_year as u64;
        year += 1;
    }
    let mut month = 1u8;
    loop {
        let days = days_in_month(year, month) as u64;
        if remaining < days {
            break;
        }
        remaining -= days;
        month += 1;
    }
    let day = remaining as u8 + 1;
    RtcTime { year, month, day, hour, minute, second, day_of_week: day_of_week(year, month, day) }
}
