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

use super::cmos::cmos_read;
use super::constants::{status_a, status_b, Register};
use super::conversion::bcd_to_bin;
use super::error::{RtcError, RtcResult};
use super::state::{get_timezone_offset, RTC_STATE, STATS_LAST_TIMESTAMP, STATS_READS};
use super::types::RtcTime;
use core::sync::atomic::Ordering;

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
    let (second_raw, minute_raw, hour_raw) = (
        cmos_read(Register::Seconds as u8),
        cmos_read(Register::Minutes as u8),
        cmos_read(Register::Hours as u8),
    );
    let (day_raw, month_raw, year_raw, dow_raw) = (
        cmos_read(Register::DayOfMonth as u8),
        cmos_read(Register::Month as u8),
        cmos_read(Register::Year as u8),
        cmos_read(Register::DayOfWeek as u8),
    );
    let status_b_val = cmos_read(Register::StatusB as u8);
    let (is_binary, is_24_hour) =
        ((status_b_val & status_b::DM) != 0, (status_b_val & status_b::HOUR_24) != 0);
    let (second, minute, day, month, year_2digit, day_of_week) = if is_binary {
        (second_raw, minute_raw, day_raw, month_raw, year_raw, dow_raw)
    } else {
        (
            bcd_to_bin(second_raw),
            bcd_to_bin(minute_raw),
            bcd_to_bin(day_raw),
            bcd_to_bin(month_raw),
            bcd_to_bin(year_raw),
            bcd_to_bin(dow_raw),
        )
    };
    let hour = if is_24_hour {
        if is_binary {
            hour_raw
        } else {
            bcd_to_bin(hour_raw)
        }
    } else {
        let pm = (hour_raw & 0x80) != 0;
        let h = if is_binary { hour_raw & 0x7F } else { bcd_to_bin(hour_raw & 0x7F) };
        match (h, pm) {
            (12, false) => 0,
            (12, true) => 12,
            (h, false) => h,
            (h, true) => h + 12,
        }
    };
    let state = RTC_STATE.read();
    let year = if state.has_century {
        let century = if is_binary {
            cmos_read(Register::Century as u8)
        } else {
            bcd_to_bin(cmos_read(Register::Century as u8))
        };
        (century as u16) * 100 + (year_2digit as u16)
    } else {
        if year_2digit < 70 {
            2000 + (year_2digit as u16)
        } else {
            1900 + (year_2digit as u16)
        }
    };
    STATS_READS.fetch_add(1, Ordering::Relaxed);
    Ok(RtcTime { year, month, day, hour, minute, second, day_of_week })
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
pub fn read_rtc_time() -> (u8, u8, u8, u8, u8, u16) {
    let t = read_rtc();
    (t.second, t.minute, t.hour, t.day, t.month, t.year)
}

pub fn read_local_time() -> RtcTime {
    let utc = read_rtc();
    let offset = get_timezone_offset();
    if offset == 0 {
        return utc;
    }
    let utc_ts = utc.to_unix_timestamp();
    let local_ts =
        if offset >= 0 { utc_ts + offset as u64 } else { utc_ts.saturating_sub((-offset) as u64) };
    RtcTime::from_unix_timestamp(local_ts)
}
