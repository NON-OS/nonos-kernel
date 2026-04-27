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

pub mod hpet_tests;
pub mod integration;
pub mod pit_tests;
pub mod registry;
pub mod rtc_tests;
pub mod runner;
pub mod timer_tests;
pub mod tsc_tests;
pub mod types;

pub use registry::TESTS;
pub use runner::{
    categories, count_category, get_test, run_all_tests, run_category, run_software_tests,
    run_test, run_tests_filtered, test_names, total_test_count,
};
pub use types::{TestCase, TestResult, TestStats};
