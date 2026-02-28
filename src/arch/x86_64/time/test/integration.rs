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

use super::types::TestResult;
use crate::arch::x86_64::time::{tsc, nonos_timer};

pub fn test_integration_tsc_timer() -> TestResult {
    if !tsc::is_calibrated() {
        return TestResult::Skipped;
    }

    let tsc_freq = tsc::get_frequency();
    let timer_source = nonos_timer::get_clock_source();

    if matches!(timer_source, nonos_timer::ClockSource::Tsc) {
        let timer_freq = nonos_timer::get_statistics().tsc_frequency;
        if timer_freq != tsc_freq {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

pub fn test_integration_time_progression() -> TestResult {
    const ITERATIONS: usize = 10;

    let mut prev_tsc = tsc::rdtsc();
    let mut prev_timer = nonos_timer::now_ns();

    for _ in 0..ITERATIONS {
        for _ in 0..10000 {
            core::hint::spin_loop();
        }

        let curr_tsc = tsc::rdtsc();
        let curr_timer = nonos_timer::now_ns();

        if curr_tsc <= prev_tsc {
            return TestResult::Failed;
        }
        if curr_timer < prev_timer {
            return TestResult::Failed;
        }

        prev_tsc = curr_tsc;
        prev_timer = curr_timer;
    }

    TestResult::Passed
}

pub fn bench_rdtsc_overhead() -> TestResult {
    const ITERATIONS: u64 = 10000;

    let start = tsc::rdtsc();
    for _ in 0..ITERATIONS {
        let _ = tsc::rdtsc();
    }
    let end = tsc::rdtsc();

    let total_ticks = end - start;
    let ticks_per_call = total_ticks / ITERATIONS;

    if ticks_per_call < 1000 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn bench_timer_now_ns() -> TestResult {
    const ITERATIONS: u64 = 1000;

    let start = tsc::rdtsc();
    for _ in 0..ITERATIONS {
        let _ = nonos_timer::now_ns();
    }
    let end = tsc::rdtsc();

    let total_ticks = end - start;
    let ticks_per_call = total_ticks / ITERATIONS;

    if ticks_per_call < 100000 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}
