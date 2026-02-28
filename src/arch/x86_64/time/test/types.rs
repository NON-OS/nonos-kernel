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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    Passed,
    Failed,
    Skipped,
    Timeout,
}

impl TestResult {
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIPPED",
            Self::Timeout => "TIMEOUT",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TestCase {
    pub name: &'static str,
    pub category: &'static str,
    pub run: fn() -> TestResult,
    pub requires_hardware: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TestStats {
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub timeout: u32,
    pub total_time_ns: u64,
}

impl TestStats {
    pub fn add_result(&mut self, result: TestResult, duration_ns: u64) {
        self.total += 1;
        self.total_time_ns += duration_ns;
        match result {
            TestResult::Passed => self.passed += 1,
            TestResult::Failed => self.failed += 1,
            TestResult::Skipped => self.skipped += 1,
            TestResult::Timeout => self.timeout += 1,
        }
    }

    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.timeout == 0
    }

    pub fn pass_rate(&self) -> u32 {
        if self.total == 0 {
            return 100;
        }
        (self.passed * 100) / self.total
    }
}

#[inline]
pub fn assert_eq<T: PartialEq + core::fmt::Debug>(actual: T, expected: T) -> bool {
    actual == expected
}

#[inline]
pub fn assert_true(condition: bool) -> bool {
    condition
}

#[inline]
pub fn assert_range<T: PartialOrd>(value: T, min: T, max: T) -> bool {
    value >= min && value <= max
}

#[inline]
pub fn assert_ok<T, E>(result: Result<T, E>) -> bool {
    result.is_ok()
}

#[inline]
pub fn assert_err<T, E>(result: Result<T, E>) -> bool {
    result.is_err()
}

pub fn bench_time_ns() -> u64 {
    crate::arch::x86_64::time::tsc::rdtsc()
}
