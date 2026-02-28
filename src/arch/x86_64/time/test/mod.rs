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

pub mod types;
pub mod tsc_tests;
pub mod hpet_tests;
pub mod pit_tests;
pub mod rtc_tests;
pub mod timer_tests;
pub mod integration;
pub mod registry;
pub mod runner;

pub use types::{TestResult, TestCase, TestStats};
pub use registry::TESTS;
pub use runner::{
    run_all_tests, run_category, run_software_tests, run_tests_filtered,
    run_test, get_test, test_names, categories, count_category, total_test_count,
};
