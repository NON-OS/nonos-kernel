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

use super::constants::{UNIX_EPOCH_YEAR, SECS_PER_DAY, SECS_PER_HOUR, SECS_PER_MIN};
use super::types::RtcTime;

#[inline]
pub const fn bcd_to_bin(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

#[inline]
pub const fn bin_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

pub const fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 => 31,
        2 => if is_leap_year(year) { 29 } else { 28 },
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 0,
    }
}

pub fn day_of_week(year: u16, month: u8, day: u8) -> u8 {
    let mut y = year as i32;
    let mut m = month as i32;

    if m < 3 {
        m += 12;
        y -= 1;
    }

    let q = day as i32;
    let k = y % 100;
    let j = y / 100;

    let h = (q + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 - 2 * j) % 7;

    let dow = ((h + 6) % 7) + 1;
    dow as u8
}

pub const fn day_name(day_of_week: u8) -> &'static str {
    match day_of_week {
        1 => "Sunday",
        2 => "Monday",
        3 => "Tuesday",
        4 => "Wednesday",
        5 => "Thursday",
        6 => "Friday",
        7 => "Saturday",
        _ => "Unknown",
    }
}

pub const fn month_name(month: u8) -> &'static str {
    match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => "Unknown",
    }
}

pub fn datetime_to_unix(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u64 {
    let mut days = 0u64;

    for y in UNIX_EPOCH_YEAR..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    for m in 1..month {
        days += days_in_month(year, m) as u64;
    }

    days += (day - 1) as u64;

    days * SECS_PER_DAY + (hour as u64) * SECS_PER_HOUR + (minute as u64) * SECS_PER_MIN + second as u64
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
    let dow = day_of_week(year, month, day);

    RtcTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        day_of_week: dow,
    }
}
