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

use super::cmos::{cmos_read, cmos_write};
use super::constants::{status_b, Register};
use super::conversion::{bin_to_bcd, day_of_week};
use super::error::RtcResult;
use super::state::{RTC_STATE, STATS_WRITES};
use super::types::RtcTime;
use core::sync::atomic::Ordering;

pub fn write_rtc(time: &RtcTime) -> RtcResult<()> {
    time.validate()?;
    let state = RTC_STATE.read();
    let (is_binary, is_24_hour) = (state.binary_mode, state.hour_24_mode);
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val | status_b::SET);
    let (second, minute, day, month) = if is_binary {
        (time.second, time.minute, time.day, time.month)
    } else {
        (
            bin_to_bcd(time.second),
            bin_to_bcd(time.minute),
            bin_to_bcd(time.day),
            bin_to_bcd(time.month),
        )
    };
    let year_2digit = (time.year % 100) as u8;
    let year = if is_binary { year_2digit } else { bin_to_bcd(year_2digit) };
    let hour = if is_24_hour {
        if is_binary {
            time.hour
        } else {
            bin_to_bcd(time.hour)
        }
    } else {
        let (h12, pm) = match time.hour {
            0 => (12, false),
            1..=11 => (time.hour, false),
            12 => (12, true),
            13..=23 => (time.hour - 12, true),
            _ => (12, false),
        };
        let h = if is_binary { h12 } else { bin_to_bcd(h12) };
        if pm {
            h | 0x80
        } else {
            h
        }
    };
    let dow = day_of_week(time.year, time.month, time.day);
    let dow_val = if is_binary { dow } else { bin_to_bcd(dow) };
    cmos_write(Register::Seconds as u8, second);
    cmos_write(Register::Minutes as u8, minute);
    cmos_write(Register::Hours as u8, hour);
    cmos_write(Register::DayOfWeek as u8, dow_val);
    cmos_write(Register::DayOfMonth as u8, day);
    cmos_write(Register::Month as u8, month);
    cmos_write(Register::Year as u8, year);
    if state.has_century {
        let century = (time.year / 100) as u8;
        cmos_write(Register::Century as u8, if is_binary { century } else { bin_to_bcd(century) });
    }
    cmos_write(Register::StatusB as u8, status_b_val & !status_b::SET);
    STATS_WRITES.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

pub fn set_unix_timestamp(timestamp: u64) -> RtcResult<()> {
    write_rtc(&RtcTime::from_unix_timestamp(timestamp))
}
