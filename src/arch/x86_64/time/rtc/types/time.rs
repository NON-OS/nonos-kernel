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

use super::super::error::{RtcError, RtcResult};
use super::super::conversion::{days_in_month, is_leap_year, day_of_week, datetime_to_unix, unix_to_datetime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub day_of_week: u8,
}

impl RtcTime {
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            day_of_week: 0,
        }
    }

    pub fn validate(&self) -> RtcResult<()> {
        if self.second > 59 {
            return Err(RtcError::InvalidTime);
        }
        if self.minute > 59 {
            return Err(RtcError::InvalidTime);
        }
        if self.hour > 23 {
            return Err(RtcError::InvalidTime);
        }

        if self.month < 1 || self.month > 12 {
            return Err(RtcError::InvalidDate);
        }
        if self.day < 1 {
            return Err(RtcError::InvalidDate);
        }

        let max_day = days_in_month(self.year, self.month);
        if self.day > max_day {
            return Err(RtcError::InvalidDate);
        }

        if self.year < 1970 || self.year > 2099 {
            return Err(RtcError::InvalidDate);
        }

        Ok(())
    }

    pub fn to_unix_timestamp(&self) -> u64 {
        datetime_to_unix(self.year, self.month, self.day, self.hour, self.minute, self.second)
    }

    pub fn from_unix_timestamp(timestamp: u64) -> Self {
        unix_to_datetime(timestamp)
    }

    pub fn calculate_day_of_week(&self) -> u8 {
        day_of_week(self.year, self.month, self.day)
    }

    pub fn with_day_of_week(mut self) -> Self {
        self.day_of_week = self.calculate_day_of_week();
        self
    }

    pub fn is_leap_year(&self) -> bool {
        is_leap_year(self.year)
    }

    pub fn day_of_year(&self) -> u16 {
        let mut day = self.day as u16;
        for m in 1..self.month {
            day += days_in_month(self.year, m) as u16;
        }
        day
    }

    pub fn format_iso8601(&self) -> [u8; 19] {
        let mut buf = [0u8; 19];

        buf[0] = b'0' + ((self.year / 1000) % 10) as u8;
        buf[1] = b'0' + ((self.year / 100) % 10) as u8;
        buf[2] = b'0' + ((self.year / 10) % 10) as u8;
        buf[3] = b'0' + (self.year % 10) as u8;
        buf[4] = b'-';

        buf[5] = b'0' + (self.month / 10);
        buf[6] = b'0' + (self.month % 10);
        buf[7] = b'-';

        buf[8] = b'0' + (self.day / 10);
        buf[9] = b'0' + (self.day % 10);
        buf[10] = b' ';

        buf[11] = b'0' + (self.hour / 10);
        buf[12] = b'0' + (self.hour % 10);
        buf[13] = b':';

        buf[14] = b'0' + (self.minute / 10);
        buf[15] = b'0' + (self.minute % 10);
        buf[16] = b':';

        buf[17] = b'0' + (self.second / 10);
        buf[18] = b'0' + (self.second % 10);

        buf
    }
}
