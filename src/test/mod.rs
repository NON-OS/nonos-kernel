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

extern crate alloc;

mod counters;
pub mod driver_tests;
pub mod framework;
pub mod memory_tests;
pub mod process_tests;
mod runner;
pub mod security_tests;

pub use counters::{get_stats, reset_counters};

pub use framework::{TestCase, TestResult, TestRunner, TestSuite};

pub use runner::run_all_tests;

pub(crate) use counters::{record_fail, record_pass, record_skip};
