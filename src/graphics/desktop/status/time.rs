// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::sys::clock;
use core::sync::atomic::{AtomicI8, Ordering};

static TIMEZONE_OFFSET: AtomicI8 = AtomicI8::new(0);

pub fn get_time_string() -> [u8; 8] {
    let mut buf = [0u8; 8];
    clock::format_time_full(&mut buf);
    buf
}

pub fn get_date_string() -> [u8; 20] {
    let mut buf = [0u8; 20];
    clock::format_date_short(&mut buf);
    buf
}

pub fn get_full_date_string() -> [u8; 32] {
    let mut buf = [0u8; 32];
    let date = get_date_string();
    for (i, &b) in date.iter().enumerate() {
        if i < 32 {
            buf[i] = b;
        }
    }
    buf
}

pub fn get_unix_timestamp() -> u64 {
    clock::unix_ms()
}

pub fn set_timezone_offset(hours: i8) {
    TIMEZONE_OFFSET.store(hours, Ordering::Relaxed);
}
pub fn get_timezone_offset() -> i8 {
    TIMEZONE_OFFSET.load(Ordering::Relaxed)
}

pub fn get_hour() -> u8 {
    let ts = clock::unix_ms() / 1000;
    let offset = TIMEZONE_OFFSET.load(Ordering::Relaxed) as i64 * 3600;
    let local_ts = (ts as i64 + offset) as u64;
    ((local_ts / 3600) % 24) as u8
}

pub fn get_minute() -> u8 {
    let ts = clock::unix_ms() / 1000;
    ((ts / 60) % 60) as u8
}

pub fn get_second() -> u8 {
    let ts = clock::unix_ms() / 1000;
    (ts % 60) as u8
}

pub fn is_24h_format() -> bool {
    true
}

pub fn get_day_of_week() -> u8 {
    let ts = clock::unix_ms() / 1000;
    let days_since_epoch = ts / 86400;
    ((days_since_epoch + 4) % 7) as u8
}

pub fn get_day_name(day: u8) -> &'static [u8] {
    match day {
        0 => b"Sunday",
        1 => b"Monday",
        2 => b"Tuesday",
        3 => b"Wednesday",
        4 => b"Thursday",
        5 => b"Friday",
        6 => b"Saturday",
        _ => b"Unknown",
    }
}

pub fn get_month_name(month: u8) -> &'static [u8] {
    match month {
        1 => b"January",
        2 => b"February",
        3 => b"March",
        4 => b"April",
        5 => b"May",
        6 => b"June",
        7 => b"July",
        8 => b"August",
        9 => b"September",
        10 => b"October",
        11 => b"November",
        12 => b"December",
        _ => b"Unknown",
    }
}
