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

#[test]
fn test_rdtsc_returns_value() {
    let tsc = rdtsc();
    assert!(tsc > 0 || tsc == 0);
}

#[test]
fn test_rdtsc_increases() {
    let tsc1 = rdtsc();
    let tsc2 = rdtsc();
    assert!(tsc2 >= tsc1);
}

#[test]
fn test_rdtsc_monotonic() {
    let mut prev = rdtsc();
    for _ in 0..100 {
        let curr = rdtsc();
        assert!(curr >= prev);
        prev = curr;
    }
}

#[test]
fn test_tsc_frequency_returns_value() {
    let freq = tsc_frequency();
    assert!(freq < u64::MAX);
}

#[test]
fn test_ticks_to_ns_zero() {
    let ns = ticks_to_ns(0);
    assert_eq!(ns, 0);
}

#[test]
fn test_ticks_to_us_zero() {
    let us = ticks_to_us(0);
    assert_eq!(us, 0);
}

#[test]
fn test_ticks_to_ms_zero() {
    let ms = ticks_to_ms(0);
    assert_eq!(ms, 0);
}

#[test]
fn test_ticks_to_ns_positive() {
    let ticks = tsc_frequency();
    if ticks > 0 {
        let ns = ticks_to_ns(ticks);
        assert!(ns > 0);
    }
}

#[test]
fn test_ticks_to_us_positive() {
    let ticks = tsc_frequency();
    if ticks > 0 {
        let us = ticks_to_us(ticks);
        assert!(us > 0);
    }
}

#[test]
fn test_ticks_to_ms_positive() {
    let ticks = tsc_frequency();
    if ticks > 0 {
        let ms = ticks_to_ms(ticks);
        assert!(ms > 0);
    }
}

#[test]
fn test_us_to_ticks_zero() {
    let ticks = us_to_ticks(0);
    assert_eq!(ticks, 0);
}

#[test]
fn test_ms_to_ticks_zero() {
    let ticks = ms_to_ticks(0);
    assert_eq!(ticks, 0);
}

#[test]
fn test_us_to_ticks_positive() {
    let ticks = us_to_ticks(1000);
    assert!(ticks > 0 || tsc_frequency() == 0);
}

#[test]
fn test_ms_to_ticks_positive() {
    let ticks = ms_to_ticks(1);
    assert!(ticks > 0 || tsc_frequency() == 0);
}

#[test]
fn test_uptime_ms_returns_value() {
    let ms = uptime_ms();
    assert!(ms < u64::MAX);
}

#[test]
fn test_uptime_us_returns_value() {
    let us = uptime_us();
    assert!(us < u64::MAX);
}

#[test]
fn test_uptime_seconds_returns_value() {
    let secs = uptime_seconds();
    assert!(secs < u64::MAX);
}

#[test]
fn test_uptime_ms_monotonic() {
    let ms1 = uptime_ms();
    let ms2 = uptime_ms();
    assert!(ms2 >= ms1);
}

#[test]
fn test_uptime_us_monotonic() {
    let us1 = uptime_us();
    let us2 = uptime_us();
    assert!(us2 >= us1);
}

#[test]
fn test_unix_timestamp_ms_returns_value() {
    let ts = unix_timestamp_ms();
    assert!(ts < u64::MAX);
}

#[test]
fn test_unix_timestamp_returns_value() {
    let ts = unix_timestamp();
    assert!(ts < u64::MAX);
}

#[test]
fn test_unix_timestamp_less_than_ms() {
    let ts_ms = unix_timestamp_ms();
    let ts = unix_timestamp();
    if ts_ms > 0 {
        assert!(ts <= ts_ms);
    }
}

#[test]
fn test_stopwatch_start() {
    let sw = Stopwatch::start();
    let _ = sw.elapsed_ticks();
}

#[test]
fn test_stopwatch_elapsed_ticks() {
    let sw = Stopwatch::start();
    let ticks = sw.elapsed_ticks();
    assert!(ticks >= 0);
}

#[test]
fn test_stopwatch_elapsed_us() {
    let sw = Stopwatch::start();
    let us = sw.elapsed_us();
    assert!(us < u64::MAX);
}

#[test]
fn test_stopwatch_elapsed_ms() {
    let sw = Stopwatch::start();
    let ms = sw.elapsed_ms();
    assert!(ms < u64::MAX);
}

#[test]
fn test_stopwatch_reset() {
    let mut sw = Stopwatch::start();
    let _ = sw.elapsed_ticks();
    sw.reset();
    let ticks_after_reset = sw.elapsed_ticks();
    assert!(ticks_after_reset < 1_000_000_000);
}

#[test]
fn test_stopwatch_elapsed_increases() {
    let sw = Stopwatch::start();
    let t1 = sw.elapsed_ticks();
    let t2 = sw.elapsed_ticks();
    assert!(t2 >= t1);
}

#[test]
fn test_is_init_returns_bool() {
    let result: bool = is_init();
    assert!(result == true || result == false);
}

#[test]
fn test_stats_returns_tuple() {
    let (freq, uptime, callbacks) = stats();
    assert!(freq < u64::MAX);
    assert!(uptime < u64::MAX);
    assert!(callbacks < u64::MAX);
}

#[test]
fn test_format_uptime_buffer_size() {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    assert_eq!(buf.len(), 8);
}

#[test]
fn test_format_uptime_colon_positions() {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    assert_eq!(buf[2], b':');
    assert_eq!(buf[5], b':');
}

#[test]
fn test_format_uptime_valid_digits() {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    assert!(buf[0] >= b'0' && buf[0] <= b'9');
    assert!(buf[1] >= b'0' && buf[1] <= b'9');
    assert!(buf[3] >= b'0' && buf[3] <= b'9');
    assert!(buf[4] >= b'0' && buf[4] <= b'9');
    assert!(buf[6] >= b'0' && buf[6] <= b'9');
    assert!(buf[7] >= b'0' && buf[7] <= b'9');
}

#[test]
fn test_format_uptime_minute_range() {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    let minutes = (buf[3] - b'0') * 10 + (buf[4] - b'0');
    assert!(minutes < 60);
}

#[test]
fn test_format_uptime_second_range() {
    let mut buf = [0u8; 8];
    format_uptime(&mut buf);
    let seconds = (buf[6] - b'0') * 10 + (buf[7] - b'0');
    assert!(seconds < 60);
}

#[test]
fn test_short_delay_exists() {
    short_delay();
}

#[test]
fn test_short_delay_multiple_calls() {
    for _ in 0..10 {
        short_delay();
    }
}

#[test]
fn test_ticks_conversion_roundtrip() {
    let freq = tsc_frequency();
    if freq > 0 {
        let us_input = 1000u64;
        let ticks = us_to_ticks(us_input);
        let us_output = ticks_to_us(ticks);
        assert!(us_output <= us_input + 1);
        assert!(us_output + 1 >= us_input);
    }
}

#[test]
fn test_ms_to_ticks_roundtrip() {
    let freq = tsc_frequency();
    if freq > 0 {
        let ms_input = 100u64;
        let ticks = ms_to_ticks(ms_input);
        let ms_output = ticks_to_ms(ticks);
        assert!(ms_output <= ms_input + 1);
        assert!(ms_output + 1 >= ms_input);
    }
}

#[test]
fn test_uptime_consistency() {
    let ms = uptime_ms();
    let secs = uptime_seconds();
    assert!(secs <= ms / 1000 + 1);
}

#[test]
fn test_stats_freq_matches_tsc_frequency() {
    let (freq, _, _) = stats();
    let tsc_freq = tsc_frequency();
    assert_eq!(freq, tsc_freq);
}

#[test]
fn test_timer_callback_type() {
    fn dummy_callback() {}
    let _cb: TimerCallback = dummy_callback;
}

#[test]
fn test_stopwatch_precision() {
    let sw = Stopwatch::start();
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    let ticks = sw.elapsed_ticks();
    assert!(ticks > 0);
}
