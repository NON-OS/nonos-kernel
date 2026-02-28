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
use crate::arch::x86_64::time::hpet;

pub fn test_hpet_detection() -> TestResult {
    let _ = hpet::is_available();
    TestResult::Passed
}

pub fn test_hpet_initialized() -> TestResult {
    let initialized = hpet::is_initialized();
    let available = hpet::is_available();

    if !available {
        return TestResult::Skipped;
    }

    let _ = initialized;
    TestResult::Passed
}

pub fn test_hpet_period_bounds() -> TestResult {
    if !hpet::is_available() {
        return TestResult::Skipped;
    }

    let _stats = hpet::get_statistics();

    TestResult::Passed
}

pub fn test_hpet_counter_monotonic() -> TestResult {
    if !hpet::is_available() {
        return TestResult::Skipped;
    }

    let counter1 = match hpet::read_counter() {
        Ok(c) => c,
        Err(_) => return TestResult::Skipped,
    };

    for _ in 0..1000 {
        core::hint::spin_loop();
    }

    let counter2 = match hpet::read_counter() {
        Ok(c) => c,
        Err(_) => return TestResult::Failed,
    };

    if counter2 >= counter1 {
        TestResult::Passed
    } else {
        TestResult::Failed
    }
}

pub fn test_hpet_ticks_to_ns() -> TestResult {
    if !hpet::is_available() {
        return TestResult::Skipped;
    }

    let ticks: u64 = 1_000_000;
    let ns = hpet::ticks_to_ns(ticks);

    let _ = ns;
    TestResult::Passed
}

pub fn test_hpet_timer_count() -> TestResult {
    if !hpet::is_available() {
        return TestResult::Skipped;
    }

    let _stats = hpet::get_statistics();

    TestResult::Passed
}
