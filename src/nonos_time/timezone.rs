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

pub fn to_timezone(timestamp_ms: u64, offset_hours: i8) -> u64 {
    let offset_ms = (offset_hours as i64) * 3600 * 1000;
    if offset_hours >= 0 {
        timestamp_ms + (offset_ms as u64)
    } else {
        timestamp_ms.saturating_sub((-offset_ms) as u64)
    }
}

pub fn utc_now() -> u64 {
    super::current_timestamp()
}
pub fn est_now() -> u64 {
    to_timezone(utc_now(), -5)
}
pub fn pst_now() -> u64 {
    to_timezone(utc_now(), -8)
}
pub fn gmt_now() -> u64 {
    utc_now()
}
pub fn cet_now() -> u64 {
    to_timezone(utc_now(), 1)
}
pub fn jst_now() -> u64 {
    to_timezone(utc_now(), 9)
}
