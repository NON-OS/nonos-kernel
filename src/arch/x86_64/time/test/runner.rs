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
use super::registry::TESTS;

pub fn run_all_tests() -> TestStats {
    run_tests_filtered(|_| true)
}

pub fn run_category(category: &str) -> TestStats {
    run_tests_filtered(|test| test.category == category)
}

pub fn run_software_tests() -> TestStats {
    run_tests_filtered(|test| !test.requires_hardware)
}

pub fn run_tests_filtered<F>(filter: F) -> TestStats
where
    F: Fn(&TestCase) -> bool,
{
    let mut stats = TestStats::default();

    for test in TESTS.iter() {
        if !filter(test) {
            continue;
        }

        let start = bench_time_ns();
        let result = (test.run)();
        let end = bench_time_ns();
        let duration = end.saturating_sub(start);

        stats.add_result(result, duration);
    }

    stats
}

pub fn run_test(name: &str) -> Option<TestResult> {
    for test in TESTS.iter() {
        if test.name == name {
            return Some((test.run)());
        }
    }
    None
}

pub fn get_test(name: &str) -> Option<&'static TestCase> {
    TESTS.iter().find(|t| t.name == name)
}

pub fn test_names() -> impl Iterator<Item = &'static str> {
    TESTS.iter().map(|t| t.name)
}

pub fn categories() -> impl Iterator<Item = &'static str> {
    static CATEGORIES: &[&str] = &["tsc", "hpet", "pit", "rtc", "timer", "integration", "benchmark"];
    CATEGORIES.iter().copied()
}

pub fn count_category(category: &str) -> usize {
    TESTS.iter().filter(|t| t.category == category).count()
}

pub fn total_test_count() -> usize {
    TESTS.len()
}
