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

use super::error::{RtcError, RtcResult};
use super::conversion::{days_in_month, is_leap_year, day_of_week, datetime_to_unix, unix_to_datetime};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcAlarm {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl RtcAlarm {
    pub const fn new(hour: u8, minute: u8, second: u8) -> Self {
        Self { hour, minute, second }
    }

    pub const fn every_second() -> Self {
        Self {
            hour: 0xFF,
            minute: 0xFF,
            second: 0xFF,
        }
    }

    pub const fn every_minute() -> Self {
        Self {
            hour: 0xFF,
            minute: 0xFF,
            second: 0,
        }
    }

    pub const fn every_hour() -> Self {
        Self {
            hour: 0xFF,
            minute: 0,
            second: 0,
        }
    }

    pub fn validate(&self) -> RtcResult<()> {
        if self.second != 0xFF && self.second > 59 {
            return Err(RtcError::InvalidAlarm);
        }
        if self.minute != 0xFF && self.minute > 59 {
            return Err(RtcError::InvalidAlarm);
        }
        if self.hour != 0xFF && self.hour > 23 {
            return Err(RtcError::InvalidAlarm);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeriodicRate {
    Disabled = 0,
    Hz256 = 1,
    Hz128 = 2,
    Hz8192 = 3,
    Hz4096 = 4,
    Hz2048 = 5,
    Hz1024 = 6,
    Hz512 = 7,
    Hz256_2 = 8,
    Hz128_2 = 9,
    Hz64 = 10,
    Hz32 = 11,
    Hz16 = 12,
    Hz8 = 13,
    Hz4 = 14,
    Hz2 = 15,
}

impl PeriodicRate {
    pub const fn value(&self) -> u8 {
        *self as u8
    }

    pub const fn frequency_hz(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Hz256 | Self::Hz256_2 => 256,
            Self::Hz128 | Self::Hz128_2 => 128,
            Self::Hz8192 => 8192,
            Self::Hz4096 => 4096,
            Self::Hz2048 => 2048,
            Self::Hz1024 => 1024,
            Self::Hz512 => 512,
            Self::Hz64 => 64,
            Self::Hz32 => 32,
            Self::Hz16 => 16,
            Self::Hz8 => 8,
            Self::Hz4 => 4,
            Self::Hz2 => 2,
        }
    }

    pub const fn period_us(&self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Hz256 | Self::Hz256_2 => 3906,
            Self::Hz128 | Self::Hz128_2 => 7812,
            Self::Hz8192 => 122,
            Self::Hz4096 => 244,
            Self::Hz2048 => 488,
            Self::Hz1024 => 976,
            Self::Hz512 => 1953,
            Self::Hz64 => 15625,
            Self::Hz32 => 31250,
            Self::Hz16 => 62500,
            Self::Hz8 => 125000,
            Self::Hz4 => 250000,
            Self::Hz2 => 500000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RtcStatistics {
    pub initialized: bool,
    pub battery_good: bool,
    pub binary_mode: bool,
    pub hour_24_mode: bool,
    pub has_century: bool,
    pub timezone_offset: i32,
    pub reads: u64,
    pub writes: u64,
    pub alarm_interrupts: u64,
    pub periodic_interrupts: u64,
    pub update_interrupts: u64,
    pub last_timestamp: u64,
}
