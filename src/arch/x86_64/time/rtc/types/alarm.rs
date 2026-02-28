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
