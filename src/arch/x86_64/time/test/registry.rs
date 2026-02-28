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

use super::types::{TestCase, TestResult, TestStats, bench_time_ns};
use super::{tsc_tests, hpet_tests, pit_tests, rtc_tests, timer_tests, integration};

pub static TESTS: &[TestCase] = &[
    TestCase {
        name: "tsc_rdtsc_basic",
        category: "tsc",
        run: tsc_tests::test_tsc_rdtsc_basic,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_rdtsc_nonzero",
        category: "tsc",
        run: tsc_tests::test_tsc_rdtsc_nonzero,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_ordering",
        category: "tsc",
        run: tsc_tests::test_tsc_ordering,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_features",
        category: "tsc",
        run: tsc_tests::test_tsc_features,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_frequency_bounds",
        category: "tsc",
        run: tsc_tests::test_tsc_frequency_bounds,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_conversion_roundtrip",
        category: "tsc",
        run: tsc_tests::test_tsc_conversion_roundtrip,
        requires_hardware: false,
    },
    TestCase {
        name: "tsc_conversion_zero_freq",
        category: "tsc",
        run: tsc_tests::test_tsc_conversion_zero_freq,
        requires_hardware: false,
    },
    TestCase {
        name: "tsc_rdtscp",
        category: "tsc",
        run: tsc_tests::test_tsc_rdtscp,
        requires_hardware: true,
    },
    TestCase {
        name: "tsc_calibration_source",
        category: "tsc",
        run: tsc_tests::test_tsc_calibration_source,
        requires_hardware: false,
    },
    TestCase {
        name: "hpet_detection",
        category: "hpet",
        run: hpet_tests::test_hpet_detection,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_initialized",
        category: "hpet",
        run: hpet_tests::test_hpet_initialized,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_period_bounds",
        category: "hpet",
        run: hpet_tests::test_hpet_period_bounds,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_counter_monotonic",
        category: "hpet",
        run: hpet_tests::test_hpet_counter_monotonic,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_ticks_to_ns",
        category: "hpet",
        run: hpet_tests::test_hpet_ticks_to_ns,
        requires_hardware: true,
    },
    TestCase {
        name: "hpet_timer_count",
        category: "hpet",
        run: hpet_tests::test_hpet_timer_count,
        requires_hardware: true,
    },
    TestCase {
        name: "pit_constants",
        category: "pit",
        run: pit_tests::test_pit_constants,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_freq_to_divisor",
        category: "pit",
        run: pit_tests::test_pit_freq_to_divisor,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_divisor_to_freq",
        category: "pit",
        run: pit_tests::test_pit_divisor_to_freq,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_period_ns",
        category: "pit",
        run: pit_tests::test_pit_period_ns,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_invalid_frequency",
        category: "pit",
        run: pit_tests::test_pit_invalid_frequency,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_channels",
        category: "pit",
        run: pit_tests::test_pit_channels,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_modes",
        category: "pit",
        run: pit_tests::test_pit_modes,
        requires_hardware: false,
    },
    TestCase {
        name: "pit_best_divisor",
        category: "pit",
        run: pit_tests::test_pit_best_divisor,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_bcd_to_bin",
        category: "rtc",
        run: rtc_tests::test_rtc_bcd_to_bin,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_time_valid",
        category: "rtc",
        run: rtc_tests::test_rtc_time_valid,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_time_invalid",
        category: "rtc",
        run: rtc_tests::test_rtc_time_invalid,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_leap_year",
        category: "rtc",
        run: rtc_tests::test_rtc_leap_year,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_days_in_month",
        category: "rtc",
        run: rtc_tests::test_rtc_days_in_month,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_day_of_week",
        category: "rtc",
        run: rtc_tests::test_rtc_day_of_week,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_unix_epoch",
        category: "rtc",
        run: rtc_tests::test_rtc_unix_epoch,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_unix_roundtrip",
        category: "rtc",
        run: rtc_tests::test_rtc_unix_roundtrip,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_alarm_validation",
        category: "rtc",
        run: rtc_tests::test_rtc_alarm_validation,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_periodic_rate",
        category: "rtc",
        run: rtc_tests::test_rtc_periodic_rate,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_format_iso8601",
        category: "rtc",
        run: rtc_tests::test_rtc_format_iso8601,
        requires_hardware: false,
    },
    TestCase {
        name: "rtc_day_of_year",
        category: "rtc",
        run: rtc_tests::test_rtc_day_of_year,
        requires_hardware: false,
    },
    TestCase {
        name: "timer_now_ns",
        category: "timer",
        run: timer_tests::test_timer_now_ns,
        requires_hardware: true,
    },
    TestCase {
        name: "timer_time_units",
        category: "timer",
        run: timer_tests::test_timer_time_units,
        requires_hardware: true,
    },
    TestCase {
        name: "timer_clock_source",
        category: "timer",
        run: timer_tests::test_timer_clock_source,
        requires_hardware: true,
    },
    TestCase {
        name: "timer_freq_period",
        category: "timer",
        run: timer_tests::test_timer_freq_period,
        requires_hardware: false,
    },
    TestCase {
        name: "timer_format_duration",
        category: "timer",
        run: timer_tests::test_timer_format_duration,
        requires_hardware: false,
    },
    TestCase {
        name: "timer_statistics",
        category: "timer",
        run: timer_tests::test_timer_statistics,
        requires_hardware: true,
    },
    TestCase {
        name: "integration_tsc_timer",
        category: "integration",
        run: integration::test_integration_tsc_timer,
        requires_hardware: true,
    },
    TestCase {
        name: "integration_time_progression",
        category: "integration",
        run: integration::test_integration_time_progression,
        requires_hardware: true,
    },
    TestCase {
        name: "bench_rdtsc_overhead",
        category: "benchmark",
        run: integration::bench_rdtsc_overhead,
        requires_hardware: true,
    },
    TestCase {
        name: "bench_timer_now_ns",
        category: "benchmark",
        run: integration::bench_timer_now_ns,
        requires_hardware: true,
    },
];
