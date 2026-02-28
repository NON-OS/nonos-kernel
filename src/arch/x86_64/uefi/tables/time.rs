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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

impl EfiTime {
    pub const TIMEZONE_UNSPECIFIED: i16 = 0x07FF;
    pub const DAYLIGHT_ADJUST: u8 = 0x01;
    pub const DAYLIGHT_IN_DAYLIGHT: u8 = 0x02;

    pub fn is_valid(&self) -> bool {
        self.year >= 1900
            && self.year <= 9999
            && self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= 31
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
            && self.nanosecond <= 999_999_999
            && (self.timezone == Self::TIMEZONE_UNSPECIFIED
                || (self.timezone >= -1440 && self.timezone <= 1440))
    }

    pub fn to_unix_timestamp(&self) -> i64 {
        let days_per_month: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

        let year = self.year as i64;
        let month = self.month as i64;
        let day = self.day as i64;

        let mut days: i64 = 0;

        for y in 1970..year {
            days += if Self::is_leap_year(y as u16) {
                366
            } else {
                365
            };
        }

        for m in 1..month {
            days += days_per_month[(m - 1) as usize];
            if m == 2 && Self::is_leap_year(year as u16) {
                days += 1;
            }
        }

        days += day - 1;

        let seconds = days * 86400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64;

        if self.timezone != Self::TIMEZONE_UNSPECIFIED {
            seconds - (self.timezone as i64 * 60)
        } else {
            seconds
        }
    }

    fn is_leap_year(year: u16) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EfiTimeCapabilities {
    pub resolution: u32,
    pub accuracy: u32,
    pub sets_to_zero: u8,
}
