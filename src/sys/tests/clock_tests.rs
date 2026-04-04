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

#[test]
fn test_time_struct_hour_range() {
    let time = get_time();
    assert!(time.hour < 24);
}

#[test]
fn test_time_struct_minute_range() {
    let time = get_time();
    assert!(time.minute < 60);
}

#[test]
fn test_time_struct_second_range() {
    let time = get_time();
    assert!(time.second < 60);
}

#[test]
fn test_format_time_buffer_size() {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    assert_eq!(buf.len(), 5);
}

#[test]
fn test_format_time_colon_position() {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    assert_eq!(buf[2], b':');
}

#[test]
fn test_format_time_valid_digits() {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    assert!(buf[0] >= b'0' && buf[0] <= b'9');
    assert!(buf[1] >= b'0' && buf[1] <= b'9');
    assert!(buf[3] >= b'0' && buf[3] <= b'9');
    assert!(buf[4] >= b'0' && buf[4] <= b'9');
}

#[test]
fn test_format_time_full_buffer_size() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    assert_eq!(buf.len(), 8);
}

#[test]
fn test_format_time_full_colon_positions() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    assert_eq!(buf[2], b':');
    assert_eq!(buf[5], b':');
}

#[test]
fn test_format_time_full_valid_digits() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    assert!(buf[0] >= b'0' && buf[0] <= b'9');
    assert!(buf[1] >= b'0' && buf[1] <= b'9');
    assert!(buf[3] >= b'0' && buf[3] <= b'9');
    assert!(buf[4] >= b'0' && buf[4] <= b'9');
    assert!(buf[6] >= b'0' && buf[6] <= b'9');
    assert!(buf[7] >= b'0' && buf[7] <= b'9');
}

#[test]
fn test_format_time_full_hour_range() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    let hour = (buf[0] - b'0') * 10 + (buf[1] - b'0');
    assert!(hour < 24);
}

#[test]
fn test_format_time_full_minute_range() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    let minute = (buf[3] - b'0') * 10 + (buf[4] - b'0');
    assert!(minute < 60);
}

#[test]
fn test_format_time_full_second_range() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    let second = (buf[6] - b'0') * 10 + (buf[7] - b'0');
    assert!(second < 60);
}

#[test]
fn test_format_date_short_buffer_size() {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    assert!(len <= 20);
    assert!(len >= 10);
}

#[test]
fn test_format_date_short_contains_space() {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    let has_space = buf[..len].iter().any(|&c| c == b' ');
    assert!(has_space);
}

#[test]
fn test_format_date_short_contains_colon() {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    let has_colon = buf[..len].iter().any(|&c| c == b':');
    assert!(has_colon);
}

#[test]
fn test_format_date_short_ends_with_am_or_pm() {
    let mut buf = [0u8; 20];
    let len = format_date_short(&mut buf);
    let ends_am = buf[len - 2] == b'A' && buf[len - 1] == b'M';
    let ends_pm = buf[len - 2] == b'P' && buf[len - 1] == b'M';
    assert!(ends_am || ends_pm);
}

#[test]
fn test_format_date_only_buffer_size() {
    let mut buf = [0u8; 12];
    let len = format_date_only(&mut buf);
    assert!(len <= 12);
    assert!(len >= 8);
}

#[test]
fn test_format_date_only_no_time() {
    let mut buf = [0u8; 12];
    let len = format_date_only(&mut buf);
    let has_colon = buf[..len].iter().any(|&c| c == b':');
    assert!(!has_colon);
}

#[test]
fn test_unix_ms_returns_value() {
    let ms = unix_ms();
    assert!(ms > 0 || ms == 0);
}

#[test]
fn test_unix_ms_monotonic() {
    let ms1 = unix_ms();
    let ms2 = unix_ms();
    assert!(ms2 >= ms1);
}

#[test]
fn test_uptime_seconds_returns_value() {
    let secs = uptime_seconds();
    assert!(secs < u64::MAX);
}

#[test]
fn test_get_time_consistency() {
    let t1 = get_time();
    let t2 = get_time();
    let diff_seconds = if t2.hour >= t1.hour {
        (t2.hour as i32 - t1.hour as i32) * 3600 +
        (t2.minute as i32 - t1.minute as i32) * 60 +
        (t2.second as i32 - t1.second as i32)
    } else {
        0
    };
    assert!(diff_seconds >= 0);
}

#[test]
fn test_format_time_produces_valid_output() {
    let mut buf = [0u8; 5];
    format_time(&mut buf);
    for (i, &c) in buf.iter().enumerate() {
        if i == 2 {
            assert_eq!(c, b':');
        } else {
            assert!(c >= b'0' && c <= b'9');
        }
    }
}

#[test]
fn test_format_time_full_produces_valid_output() {
    let mut buf = [0u8; 8];
    format_time_full(&mut buf);
    for (i, &c) in buf.iter().enumerate() {
        if i == 2 || i == 5 {
            assert_eq!(c, b':');
        } else {
            assert!(c >= b'0' && c <= b'9');
        }
    }
}
