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

use super::constants::{Register, status_b};
use super::error::RtcResult;
use super::types::RtcAlarm;
use super::cmos::{cmos_read, cmos_write};
use super::conversion::bin_to_bcd;
use super::state::RTC_STATE;

pub fn set_alarm(alarm: &RtcAlarm) -> RtcResult<()> {
    alarm.validate()?;

    let state = RTC_STATE.read();
    let is_binary = state.binary_mode;

    let second = if alarm.second == 0xFF {
        0xFF
    } else if is_binary {
        alarm.second
    } else {
        bin_to_bcd(alarm.second)
    };

    let minute = if alarm.minute == 0xFF {
        0xFF
    } else if is_binary {
        alarm.minute
    } else {
        bin_to_bcd(alarm.minute)
    };

    let hour = if alarm.hour == 0xFF {
        0xFF
    } else if is_binary {
        alarm.hour
    } else {
        bin_to_bcd(alarm.hour)
    };

    cmos_write(Register::SecondsAlarm as u8, second);
    cmos_write(Register::MinutesAlarm as u8, minute);
    cmos_write(Register::HoursAlarm as u8, hour);

    Ok(())
}

pub fn enable_alarm() -> RtcResult<()> {
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val | status_b::AIE);

    let mut state = RTC_STATE.write();
    state.alarm_enabled = true;

    Ok(())
}

pub fn disable_alarm() {
    let status_b_val = cmos_read(Register::StatusB as u8);
    cmos_write(Register::StatusB as u8, status_b_val & !status_b::AIE);

    let mut state = RTC_STATE.write();
    state.alarm_enabled = false;
}

pub fn is_alarm_enabled() -> bool {
    RTC_STATE.read().alarm_enabled
}
