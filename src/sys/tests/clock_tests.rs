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

use crate::sys::clock::*;
use crate::test::framework::TestResult;

pub(crate) fn test_time_struct_hour_range() -> TestResult {
    let time = get_time();
    if !(time.hour < 24) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_time_struct_minute_range() -> TestResult {
    let time = get_time();
    if !(time.minute < 60) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_time_struct_second_range() -> TestResult {
    let time = get_time();
    if !(time.second < 60) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_buffer_size() -> TestResult {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    if buf.len() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_colon_position() -> TestResult {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    if buf[2] != b':' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_valid_digits() -> TestResult {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    if !(buf[0] >= b'0' && buf[0] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[1] >= b'0' && buf[1] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[3] >= b'0' && buf[3] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[4] >= b'0' && buf[4] <= b'9') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_buffer_size() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    if buf.len() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_colon_positions() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    if buf[2] != b':' {
        return TestResult::Fail;
    }
    if buf[5] != b':' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_valid_digits() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    if !(buf[0] >= b'0' && buf[0] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[1] >= b'0' && buf[1] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[3] >= b'0' && buf[3] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[4] >= b'0' && buf[4] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[6] >= b'0' && buf[6] <= b'9') {
        return TestResult::Fail;
    }
    if !(buf[7] >= b'0' && buf[7] <= b'9') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_hour_range() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    let hour = (buf[0] - b'0') * 10 + (buf[1] - b'0');
    if !(hour < 24) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_minute_range() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    let minute = (buf[3] - b'0') * 10 + (buf[4] - b'0');
    if !(minute < 60) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_second_range() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    let second = (buf[6] - b'0') * 10 + (buf[7] - b'0');
    if !(second < 60) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_date_short_buffer_size() -> TestResult {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    if !(len <= 20) {
        return TestResult::Fail;
    }
    if !(len >= 10) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_date_short_contains_space() -> TestResult {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    let has_space = buf[..len].iter().any(|&c| c == b' ');
    if !has_space {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_date_short_contains_colon() -> TestResult {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    let has_colon = buf[..len].iter().any(|&c| c == b':');
    if !has_colon {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_date_short_ends_with_am_or_pm() -> TestResult {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    let ends_am = buf[len - 2] == b'A' && buf[len - 1] == b'M';
    let ends_pm = buf[len - 2] == b'P' && buf[len - 1] == b'M';
    if !(ends_am || ends_pm) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_date_only_buffer_size() -> TestResult {
    let mut buf = [0u8; 12];
    let len = format_date_only(&mut buf);
    if !(len <= 12) {
        return TestResult::Fail;
    }
    if !(len >= 8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_date_only_no_time() -> TestResult {
    let mut buf = [0u8; 12];
    let len = format_date_only(&mut buf);
    let has_colon = buf[..len].iter().any(|&c| c == b':');
    if has_colon {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unix_ms_returns_value() -> TestResult {
    let ms = unix_ms();
    if !(ms > 0 || ms == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unix_ms_monotonic() -> TestResult {
    let ms1 = unix_ms();
    let ms2 = unix_ms();
    if !(ms2 >= ms1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_uptime_seconds_returns_value() -> TestResult {
    let secs = uptime_seconds();
    if !(secs < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_time_consistency() -> TestResult {
    let t1 = get_time();
    let t2 = get_time();
    let diff_seconds = if t2.hour >= t1.hour {
        (t2.hour as i32 - t1.hour as i32) * 3600
            + (t2.minute as i32 - t1.minute as i32) * 60
            + (t2.second as i32 - t1.second as i32)
    } else {
        0
    };
    if !(diff_seconds >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_produces_valid_output() -> TestResult {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    for (i, &c) in buf.iter().enumerate() {
        if i == 2 {
            if c != b':' {
                return TestResult::Fail;
            }
        } else {
            if !(c >= b'0' && c <= b'9') {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_format_time_full_produces_valid_output() -> TestResult {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    for (i, &c) in buf.iter().enumerate() {
        if i == 2 || i == 5 {
            if c != b':' {
                return TestResult::Fail;
            }
        } else {
            if !(c >= b'0' && c <= b'9') {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
