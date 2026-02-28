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
use super::constants::{Register, status_a, status_b};
use super::error::{RtcError, RtcResult};
use super::types::RtcTime;
use super::cmos::{cmos_read, cmos_write};
use super::conversion::{bcd_to_bin, bin_to_bcd, day_of_week};
use super::state::{RTC_STATE, STATS_READS, STATS_WRITES, STATS_LAST_TIMESTAMP, get_timezone_offset};

fn wait_for_update() -> RtcResult<()> {
    let mut timeout = 10000u32;
    while (cmos_read(Register::StatusA as u8) & status_a::UIP) != 0 && timeout > 0 {
        timeout -= 1;
        core::hint::spin_loop();
    }
    if timeout == 0 {
        Err(RtcError::UpdateInProgress)
    } else {
        Ok(())
    }
}

fn read_rtc_internal() -> RtcResult<RtcTime> {
    wait_for_update()?;

    let second_raw = cmos_read(Register::Seconds as u8);
    let minute_raw = cmos_read(Register::Minutes as u8);
    let hour_raw = cmos_read(Register::Hours as u8);
    let day_raw = cmos_read(Register::DayOfMonth as u8);
    let month_raw = cmos_read(Register::Month as u8);
    let year_raw = cmos_read(Register::Year as u8);
    let dow_raw = cmos_read(Register::DayOfWeek as u8);

    let status_b_val = cmos_read(Register::StatusB as u8);
    let is_binary = (status_b_val & status_b::DM) != 0;
    let is_24_hour = (status_b_val & status_b::HOUR_24) != 0;

    let second = if is_binary { second_raw } else { bcd_to_bin(second_raw) };
    let minute = if is_binary { minute_raw } else { bcd_to_bin(minute_raw) };
    let day = if is_binary { day_raw } else { bcd_to_bin(day_raw) };
    let month = if is_binary { month_raw } else { bcd_to_bin(month_raw) };
    let year_2digit = if is_binary { year_raw } else { bcd_to_bin(year_raw) };
    let day_of_week = if is_binary { dow_raw } else { bcd_to_bin(dow_raw) };

    let hour = if is_24_hour {
        if is_binary { hour_raw } else { bcd_to_bin(hour_raw) }
    } else {
        let pm = (hour_raw & 0x80) != 0;
        let h = if is_binary {
            hour_raw & 0x7F
        } else {
            bcd_to_bin(hour_raw & 0x7F)
        };
        match (h, pm) {
            (12, false) => 0,
            (12, true) => 12,
            (h, false) => h,
            (h, true) => h + 12,
        }
    };

    let state = RTC_STATE.read();
    let year = if state.has_century {
        let century_raw = cmos_read(Register::Century as u8);
        let century = if is_binary { century_raw } else { bcd_to_bin(century_raw) };
        (century as u16) * 100 + (year_2digit as u16)
    } else {
        if year_2digit < 70 {
            2000 + (year_2digit as u16)
        } else {
            1900 + (year_2digit as u16)
        }
    };

    STATS_READS.fetch_add(1, Ordering::Relaxed);

    Ok(RtcTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        day_of_week,
    })
}

pub fn read_rtc() -> RtcTime {
    read_rtc_internal().unwrap_or_default()
}

pub fn read_rtc_checked() -> RtcResult<RtcTime> {
    read_rtc_internal()
}

pub fn read_unix_timestamp() -> u64 {
    let time = read_rtc();
    let ts = time.to_unix_timestamp();
    STATS_LAST_TIMESTAMP.store(ts, Ordering::Relaxed);
    ts
}

pub fn write_rtc(time: &RtcTime) -> RtcResult<()> {
    time.validate()?;

    let state = RTC_STATE.read();
    let is_binary = state.binary_mode;
    let is_24_hour = state.hour_24_mode;

    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val | status_b::SET);

    let second = if is_binary { time.second } else { bin_to_bcd(time.second) };
    let minute = if is_binary { time.minute } else { bin_to_bcd(time.minute) };
    let day = if is_binary { time.day } else { bin_to_bcd(time.day) };
    let month = if is_binary { time.month } else { bin_to_bcd(time.month) };
    let year_2digit = (time.year % 100) as u8;
    let year = if is_binary { year_2digit } else { bin_to_bcd(year_2digit) };

    let hour = if is_24_hour {
        if is_binary { time.hour } else { bin_to_bcd(time.hour) }
    } else {
        let (h12, pm) = match time.hour {
            0 => (12, false),
            1..=11 => (time.hour, false),
            12 => (12, true),
            13..=23 => (time.hour - 12, true),
            _ => (12, false),
        };
        let h = if is_binary { h12 } else { bin_to_bcd(h12) };
        if pm { h | 0x80 } else { h }
    };

    let dow = day_of_week(time.year, time.month, time.day);
    let day_of_week_val = if is_binary { dow } else { bin_to_bcd(dow) };

    cmos_write(Register::Seconds as u8, second);
    cmos_write(Register::Minutes as u8, minute);
    cmos_write(Register::Hours as u8, hour);
    cmos_write(Register::DayOfWeek as u8, day_of_week_val);
    cmos_write(Register::DayOfMonth as u8, day);
    cmos_write(Register::Month as u8, month);
    cmos_write(Register::Year as u8, year);

    if state.has_century {
        let century = (time.year / 100) as u8;
        let cent = if is_binary { century } else { bin_to_bcd(century) };
        cmos_write(Register::Century as u8, cent);
    }

    cmos_write(Register::StatusB as u8, status_b_val & !status_b::SET);

    STATS_WRITES.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn set_unix_timestamp(timestamp: u64) -> RtcResult<()> {
    let time = RtcTime::from_unix_timestamp(timestamp);
    write_rtc(&time)
}

pub fn read_local_time() -> RtcTime {
    let utc = read_rtc();
    let offset = get_timezone_offset();

    if offset == 0 {
        return utc;
    }

    let utc_ts = utc.to_unix_timestamp();
    let local_ts = if offset >= 0 {
        utc_ts + offset as u64
    } else {
        utc_ts.saturating_sub((-offset) as u64)
    };

    RtcTime::from_unix_timestamp(local_ts)
}

pub fn read_rtc_time() -> (u8, u8, u8, u8, u8, u16) {
    let time = read_rtc();
    (time.second, time.minute, time.hour, time.day, time.month, time.year)
}
