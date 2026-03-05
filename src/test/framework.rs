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

//! Test Framework Core - Macros and utilities for kernel testing

extern crate alloc;

use alloc::vec::Vec;

/// Result of a single test
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Fail,
    Skip,
}

/// A single test case
pub struct TestCase {
    pub name: &'static str,
    pub func: fn() -> TestResult,
    pub category: &'static str,
}

impl TestCase {
    pub const fn new(name: &'static str, func: fn() -> TestResult, category: &'static str) -> Self {
        Self { name, func, category }
    }

    pub fn run(&self) -> TestResult {
        (self.func)()
    }
}

/// A collection of related tests
pub struct TestSuite {
    pub name: &'static str,
    pub tests: Vec<TestCase>,
}

impl TestSuite {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            tests: Vec::new(),
        }
    }

    pub fn add_test(&mut self, test: TestCase) {
        self.tests.push(test);
    }

    pub fn run_all(&self) -> (u32, u32, u32) {
        use crate::drivers::console;

        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut skipped = 0u32;

        for test in &self.tests {
            let result = test.run();
            match result {
                TestResult::Pass => {
                    console::write_message(&alloc::format!("  [PASS] {}", test.name));
                    passed += 1;
                    super::record_pass();
                }
                TestResult::Fail => {
                    console::write_message(&alloc::format!("  [FAIL] {}", test.name));
                    failed += 1;
                    super::record_fail();
                }
                TestResult::Skip => {
                    console::write_message(&alloc::format!("  [SKIP] {}", test.name));
                    skipped += 1;
                    super::record_skip();
                }
            }
        }

        (passed, failed, skipped)
    }
}

/// Test runner for executing multiple suites
pub struct TestRunner {
    suites: Vec<TestSuite>,
}

impl TestRunner {
    pub fn new() -> Self {
        Self { suites: Vec::new() }
    }

    pub fn add_suite(&mut self, suite: TestSuite) {
        self.suites.push(suite);
    }

    pub fn run_all(&self) -> bool {
        let mut all_passed = true;

        for suite in &self.suites {
            let (_, failed, _) = suite.run_all();
            if failed > 0 {
                all_passed = false;
            }
        }

        all_passed
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ASSERTION MACROS FOR KERNEL TESTS
// ═══════════════════════════════════════════════════════════════════════════

/// Assert that a condition is true
#[macro_export]
macro_rules! test_assert {
    ($cond:expr) => {
        if !$cond {
            return $crate::test::framework::TestResult::Fail;
        }
    };
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Assert equality
#[macro_export]
macro_rules! test_assert_eq {
    ($left:expr, $right:expr) => {
        if $left != $right {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Assert inequality
#[macro_export]
macro_rules! test_assert_ne {
    ($left:expr, $right:expr) => {
        if $left == $right {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Assert that a value is Some
#[macro_export]
macro_rules! test_assert_some {
    ($opt:expr) => {
        if $opt.is_none() {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Assert that a value is None
#[macro_export]
macro_rules! test_assert_none {
    ($opt:expr) => {
        if $opt.is_some() {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Assert that a Result is Ok
#[macro_export]
macro_rules! test_assert_ok {
    ($result:expr) => {
        if $result.is_err() {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Assert that a Result is Err
#[macro_export]
macro_rules! test_assert_err {
    ($result:expr) => {
        if $result.is_ok() {
            return $crate::test::framework::TestResult::Fail;
        }
    };
}

/// Skip test if condition is not met
#[macro_export]
macro_rules! test_skip_if {
    ($cond:expr) => {
        if $cond {
            return $crate::test::framework::TestResult::Skip;
        }
    };
}

/// Mark test as passed
#[macro_export]
macro_rules! test_pass {
    () => {
        return $crate::test::framework::TestResult::Pass;
    };
}

/// Mark test as failed
#[macro_export]
macro_rules! test_fail {
    () => {
        return $crate::test::framework::TestResult::Fail;
    };
}
