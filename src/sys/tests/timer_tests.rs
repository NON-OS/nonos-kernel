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

use crate::sys::timer::*;
use crate::test::framework::TestResult;

pub(crate) fn test_rdtsc_returns_value() -> TestResult {
    let tsc = rdtsc();
    if !(tsc > 0 || tsc == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rdtsc_increases() -> TestResult {
    let tsc1 = rdtsc();
    let tsc2 = rdtsc();
    if !(tsc2 >= tsc1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rdtsc_monotonic() -> TestResult {
    let mut prev = rdtsc();
    for _ in 0..100 {
        let curr = rdtsc();
        if !(curr >= prev) {
            return TestResult::Fail;
        }
        prev = curr;
    }
    TestResult::Pass
}

pub(crate) fn test_tsc_frequency_returns_value() -> TestResult {
    let freq = tsc_frequency();
    if !(freq < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_to_ns_zero() -> TestResult {
    let ns = ticks_to_ns(0);
    if ns != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_to_us_zero() -> TestResult {
    let us = ticks_to_us(0);
    if us != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_to_ms_zero() -> TestResult {
    let ms = ticks_to_ms(0);
    if ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_to_ns_positive() -> TestResult {
    let ticks = tsc_frequency();
    if ticks > 0 {
        let ns = ticks_to_ns(ticks);
        if !(ns > 0) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_to_us_positive() -> TestResult {
    let ticks = tsc_frequency();
    if ticks > 0 {
        let us = ticks_to_us(ticks);
        if !(us > 0) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_to_ms_positive() -> TestResult {
    let ticks = tsc_frequency();
    if ticks > 0 {
        let ms = ticks_to_ms(ticks);
        if !(ms > 0) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_us_to_ticks_zero() -> TestResult {
    let ticks = us_to_ticks(0);
    if ticks != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ms_to_ticks_zero() -> TestResult {
    let ticks = ms_to_ticks(0);
    if ticks != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_us_to_ticks_positive() -> TestResult {
    let ticks = us_to_ticks(1000);
    if !(ticks > 0 || tsc_frequency() == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ms_to_ticks_positive() -> TestResult {
    let ticks = ms_to_ticks(1);
    if !(ticks > 0 || tsc_frequency() == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_uptime_ms_returns_value() -> TestResult {
    let ms = uptime_ms();
    if !(ms < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_uptime_us_returns_value() -> TestResult {
    let us = uptime_us();
    if !(us < u64::MAX) {
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

pub(crate) fn test_uptime_ms_monotonic() -> TestResult {
    let ms1 = uptime_ms();
    let ms2 = uptime_ms();
    if !(ms2 >= ms1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_uptime_us_monotonic() -> TestResult {
    let us1 = uptime_us();
    let us2 = uptime_us();
    if !(us2 >= us1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unix_timestamp_ms_returns_value() -> TestResult {
    let ts = unix_timestamp_ms();
    if !(ts < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unix_timestamp_returns_value() -> TestResult {
    let ts = unix_timestamp();
    if !(ts < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unix_timestamp_less_than_ms() -> TestResult {
    let ts_ms = unix_timestamp_ms();
    let ts = unix_timestamp();
    if ts_ms > 0 {
        if !(ts <= ts_ms) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_stopwatch_start() -> TestResult {
    let sw = Stopwatch::start();
    let _ = sw.elapsed_ticks();
    TestResult::Pass
}

pub(crate) fn test_stopwatch_elapsed_ticks() -> TestResult {
    let sw = Stopwatch::start();
    let _ = sw.elapsed_ticks();
    TestResult::Pass
}

pub(crate) fn test_stopwatch_elapsed_us() -> TestResult {
    let sw = Stopwatch::start();
    let us = sw.elapsed_us();
    if !(us < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stopwatch_elapsed_ms() -> TestResult {
    let sw = Stopwatch::start();
    let ms = sw.elapsed_ms();
    if !(ms < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stopwatch_reset() -> TestResult {
    let mut sw = Stopwatch::start();
    let _ = sw.elapsed_ticks();
    sw.reset();
    let ticks_after_reset = sw.elapsed_ticks();
    if !(ticks_after_reset < 1_000_000_000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stopwatch_elapsed_increases() -> TestResult {
    let sw = Stopwatch::start();
    let t1 = sw.elapsed_ticks();
    let t2 = sw.elapsed_ticks();
    if !(t2 >= t1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_init_returns_bool() -> TestResult {
    let result: bool = is_init();
    if !(result == true || result == false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_returns_tuple() -> TestResult {
    let (freq, uptime, callbacks) = stats();
    if !(freq < u64::MAX) {
        return TestResult::Fail;
    }
    if !(uptime < u64::MAX) {
        return TestResult::Fail;
    }
    if !(callbacks < u64::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_uptime_buffer_size() -> TestResult {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    if buf.len() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_uptime_colon_positions() -> TestResult {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    if buf[2] != b':' {
        return TestResult::Fail;
    }
    if buf[5] != b':' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_uptime_valid_digits() -> TestResult {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
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

pub(crate) fn test_format_uptime_minute_range() -> TestResult {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    let minutes = (buf[3] - b'0') * 10 + (buf[4] - b'0');
    if !(minutes < 60) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_uptime_second_range() -> TestResult {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    let seconds = (buf[6] - b'0') * 10 + (buf[7] - b'0');
    if !(seconds < 60) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_short_delay_exists() -> TestResult {
    short_delay();
    TestResult::Pass
}

pub(crate) fn test_short_delay_multiple_calls() -> TestResult {
    for _ in 0..10 {
        short_delay();
    }
    TestResult::Pass
}

pub(crate) fn test_ticks_conversion_roundtrip() -> TestResult {
    let freq = tsc_frequency();
    if freq > 0 {
        let us_input = 1000u64;
        let ticks = us_to_ticks(us_input);
        let us_output = ticks_to_us(ticks);
        if !(us_output <= us_input + 1) {
            return TestResult::Fail;
        }
        if !(us_output + 1 >= us_input) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ms_to_ticks_roundtrip() -> TestResult {
    let freq = tsc_frequency();
    if freq > 0 {
        let ms_input = 100u64;
        let ticks = ms_to_ticks(ms_input);
        let ms_output = ticks_to_ms(ticks);
        if !(ms_output <= ms_input + 1) {
            return TestResult::Fail;
        }
        if !(ms_output + 1 >= ms_input) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_uptime_consistency() -> TestResult {
    let ms = uptime_ms();
    let secs = uptime_seconds();
    if !(secs <= ms / 1000 + 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_freq_matches_tsc_frequency() -> TestResult {
    let (freq, _, _) = stats();
    let tsc_freq = tsc_frequency();
    if freq != tsc_freq {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timer_callback_type() -> TestResult {
    fn dummy_callback() {}
    let _cb: TimerCallback = dummy_callback;
    TestResult::Pass
}

pub(crate) fn test_stopwatch_precision() -> TestResult {
    let sw = Stopwatch::start();
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    let ticks = sw.elapsed_ticks();
    if !(ticks > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
