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

use super::core::unix_ms;
use super::time::get_time;

pub fn format_time(buf: &mut [u8; 5]) {
    let time = get_time();

    buf[0] = b'0' + (time.hour / 10);
    buf[1] = b'0' + (time.hour % 10);
    buf[2] = b':';
    buf[3] = b'0' + (time.minute / 10);
    buf[4] = b'0' + (time.minute % 10);
}

pub fn format_time_full(buf: &mut [u8; 8]) {
    let time = get_time();

    buf[0] = b'0' + (time.hour / 10);
    buf[1] = b'0' + (time.hour % 10);
    buf[2] = b':';
    buf[3] = b'0' + (time.minute / 10);
    buf[4] = b'0' + (time.minute % 10);
    buf[5] = b':';
    buf[6] = b'0' + (time.second / 10);
    buf[7] = b'0' + (time.second % 10);
}

pub fn format_date_short(buf: &mut [u8; 20]) -> usize {
    let ms = unix_ms();
    let total_days = (ms / 1000 / 86400) as u32;
    let time = get_time();

    let mut year = 1970u32;
    let mut remaining = total_days;
    loop {
        let days_in_year = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 { 366 } else { 365 };
        if remaining < days_in_year { break; }
        remaining -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_months: [u32; 12] = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0usize;
    for (i, &days) in days_in_months.iter().enumerate() {
        if remaining < days { month = i; break; }
        remaining -= days;
    }
    let day = remaining + 1;

    let dow = (total_days + 4) % 7;
    let dow_names: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
    let mon_names: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

    let hour_12 = if time.hour == 0 { 12 } else if time.hour > 12 { time.hour - 12 } else { time.hour };
    let am_pm = if time.hour < 12 { b"AM" } else { b"PM" };

    let mut pos = 0usize;
    buf[pos..pos+3].copy_from_slice(dow_names[dow as usize]);
    pos += 3;
    buf[pos] = b' ';
    pos += 1;
    buf[pos..pos+3].copy_from_slice(mon_names[month]);
    pos += 3;
    buf[pos] = b' ';
    pos += 1;
    if day >= 10 { buf[pos] = b'0' + (day / 10) as u8; pos += 1; }
    buf[pos] = b'0' + (day % 10) as u8;
    pos += 1;
    buf[pos] = b' ';
    pos += 1;
    if hour_12 >= 10 { buf[pos] = b'0' + (hour_12 / 10); pos += 1; }
    buf[pos] = b'0' + (hour_12 % 10);
    pos += 1;
    buf[pos] = b':';
    pos += 1;
    buf[pos] = b'0' + (time.minute / 10);
    pos += 1;
    buf[pos] = b'0' + (time.minute % 10);
    pos += 1;
    buf[pos] = am_pm[0];
    pos += 1;
    buf[pos] = am_pm[1];
    pos += 1;

    pos
}
