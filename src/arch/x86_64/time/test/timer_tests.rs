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
use crate::arch::x86_64::time::nonos_timer;

pub fn test_timer_now_ns() -> TestResult {
    let t1 = nonos_timer::now_ns();
    let t2 = nonos_timer::now_ns();

    if t2 >= t1 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn test_timer_time_units() -> TestResult {
    let ns = nonos_timer::now_ns();
    let us = nonos_timer::now_us();
    let ms = nonos_timer::now_ms();

    if ns > 0 {
        if us > ns {
            return TestResult::Failed;
        }
        if ms > us {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

pub fn test_timer_clock_source() -> TestResult {
    let source = nonos_timer::get_clock_source();
    let name = source.name();

    if name.is_empty() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_timer_freq_period() -> TestResult {
    let period = nonos_timer::freq_to_period_ns(1_000_000);
    if period != 1_000 {
        return TestResult::Failed;
    }

    let freq = nonos_timer::period_ns_to_freq(1_000);
    if freq != 1_000_000 {
        return TestResult::Failed;
    }

    if nonos_timer::freq_to_period_ns(0) != 0 {
        return TestResult::Failed;
    }
    if nonos_timer::period_ns_to_freq(0) != 0 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_timer_format_duration() -> TestResult {
    let ns = nonos_timer::format_duration_ns(500);
    if !ns.ends_with("ns") {
        return TestResult::Failed;
    }

    let us = nonos_timer::format_duration_ns(1_500);
    if !us.ends_with("us") {
        return TestResult::Failed;
    }

    let ms = nonos_timer::format_duration_ns(1_500_000);
    if !ms.ends_with("ms") {
        return TestResult::Failed;
    }

    let s = nonos_timer::format_duration_ns(1_500_000_000);
    if !s.ends_with("s") {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_timer_statistics() -> TestResult {
    let stats = nonos_timer::get_statistics();

    if stats.uptime_ns > 1_000_000_000_000_000 {
        return TestResult::Failed;
    }

    TestResult::Passed
}
