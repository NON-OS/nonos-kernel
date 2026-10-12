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

use alloc::format;
use alloc::string::String;

const HOUR_MS: i64 = 3_600_000;
const MINUTE_MS: i64 = 60_000;

/// A greeting for the UTC hour of wall-clock `ms`; "Hello" when the clock
/// has not been set.
pub fn hour_greeting(ms: i64) -> &'static str {
    if ms <= 0 {
        return "Hello";
    }
    match (ms / HOUR_MS) % 24 {
        5..=11 => "Good morning",
        12..=17 => "Good afternoon",
        _ => "Good evening",
    }
}

/// `HH:MM` for the UTC time of wall-clock `ms`; a negative clock reads as zero.
pub fn hhmm(ms: i64) -> String {
    let minutes = ms.max(0) / MINUTE_MS;
    format!("{:02}:{:02}", (minutes / 60) % 24, minutes % 60)
}

/// How long before wall-clock `now_ms` the moment `at_ms` was, for people:
/// `just now` under a minute (or in the future), then minutes, hours, days.
pub fn ago(now_ms: i64, at_ms: i64) -> String {
    let secs = now_ms.saturating_sub(at_ms) / 1000;
    match secs {
        ..60 => String::from("just now"),
        60..3600 => format!("{} min ago", secs / 60),
        3600..86_400 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86_400),
    }
}
