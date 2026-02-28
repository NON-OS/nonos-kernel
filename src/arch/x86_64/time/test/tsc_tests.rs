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
use crate::arch::x86_64::time::tsc;

pub fn test_tsc_rdtsc_basic() -> TestResult {
    let t0 = tsc::rdtsc();
    let t1 = tsc::rdtsc();

    if t1 >= t0 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn test_tsc_rdtsc_nonzero() -> TestResult {
    let t = tsc::rdtsc();

    if t > 0 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn test_tsc_ordering() -> TestResult {
    const ITERATIONS: usize = 100;
    let mut prev = tsc::rdtsc();

    for _ in 0..ITERATIONS {
        let current = tsc::rdtsc();
        if current < prev {
            return TestResult::Failed;
        }
        prev = current;
    }

    TestResult::Passed
}

pub fn test_tsc_features() -> TestResult {
    let features = tsc::detect_features();

    if !features.tsc_available {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_tsc_frequency_bounds() -> TestResult {
    let freq = tsc::get_frequency();

    if freq > 0 {
        if freq < 100_000_000 || freq > 10_000_000_000 {
            return TestResult::Failed;
        }
    }

    TestResult::Passed
}

pub fn test_tsc_conversion_roundtrip() -> TestResult {
    let freq: u64 = 3_000_000_000;

    let ns: u64 = 1_000_000_000;
    let ticks = tsc::ns_to_tsc(ns, freq);
    let ns_back = tsc::tsc_to_ns(ticks, freq);

    let error = if ns_back > ns { ns_back - ns } else { ns - ns_back };
    let max_error = ns / 100;

    if error <= max_error {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn test_tsc_conversion_zero_freq() -> TestResult {
    let result1 = tsc::tsc_to_ns(1000, 0);
    let result2 = tsc::ns_to_tsc(1000, 0);

    if result1 == 0 && result2 == 0 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn test_tsc_rdtscp() -> TestResult {
    let features = tsc::detect_features();

    if !features.rdtscp_available {
        return TestResult::Skipped;
    }

    let (tsc_val, aux) = tsc::rdtscp();

    if tsc_val == 0 {
        return TestResult::Failed;
    }

    let _ = aux;

    TestResult::Passed
}

pub fn test_tsc_calibration_source() -> TestResult {
    let source = tsc::get_calibration_source();

    let name = source.name();
    if name.is_empty() {
        return TestResult::Failed;
    }

    let rating = source.accuracy_rating();
    if rating > 5 {
        return TestResult::Failed;
    }

    TestResult::Passed
}
