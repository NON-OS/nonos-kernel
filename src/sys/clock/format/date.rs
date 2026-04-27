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

use super::helpers::{date_from_secs, local_unix_secs, DOW_NAMES, MON_NAMES};
use crate::sys::clock::time::get_time;

pub fn format_date_short(buf: &mut [u8; 20]) -> usize {
    let parts = date_from_secs(local_unix_secs());
    let time = get_time();
    let hour_12 = if time.hour == 0 {
        12
    } else if time.hour > 12 {
        time.hour - 12
    } else {
        time.hour
    };
    let am_pm = if time.hour < 12 { b"AM" } else { b"PM" };
    let mut pos = 0usize;
    buf[pos..pos + 3].copy_from_slice(DOW_NAMES[parts.dow as usize]);
    pos += 3;
    buf[pos] = b' ';
    pos += 1;
    buf[pos..pos + 3].copy_from_slice(MON_NAMES[parts.month]);
    pos += 3;
    buf[pos] = b' ';
    pos += 1;
    if parts.day >= 10 {
        buf[pos] = b'0' + (parts.day / 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (parts.day % 10) as u8;
    pos += 1;
    buf[pos] = b' ';
    pos += 1;
    if hour_12 >= 10 {
        buf[pos] = b'0' + (hour_12 / 10);
        pos += 1;
    }
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

pub fn format_date_only(buf: &mut [u8; 12]) -> usize {
    let parts = date_from_secs(local_unix_secs());
    let mut pos = 0usize;
    buf[pos..pos + 3].copy_from_slice(DOW_NAMES[parts.dow as usize]);
    pos += 3;
    buf[pos] = b' ';
    pos += 1;
    buf[pos..pos + 3].copy_from_slice(MON_NAMES[parts.month]);
    pos += 3;
    buf[pos] = b' ';
    pos += 1;
    if parts.day >= 10 {
        buf[pos] = b'0' + (parts.day / 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (parts.day % 10) as u8;
    pos += 1;
    pos
}
