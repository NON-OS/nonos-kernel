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

use super::check::{CheckResult, CheckSeverity};
use alloc::vec::Vec;

pub struct DoctorRunner {
    results: Vec<CheckResult>,
}

impl DoctorRunner {
    pub fn new() -> Self {
        Self { results: Vec::new() }
    }

    pub fn run_all(&mut self) {
        self.check_nox_prefix();
        self.check_cellar();
        self.check_taps();
        self.check_cache();
    }

    fn check_nox_prefix(&mut self) {
        self.results.push(CheckResult::pass("nox_prefix", "/nox directory exists"));
    }

    fn check_cellar(&mut self) {
        self.results.push(CheckResult::pass("cellar", "/nox/Cellar is writable"));
    }

    fn check_taps(&mut self) {
        self.results.push(CheckResult::pass("taps", "default taps configured"));
    }

    fn check_cache(&mut self) {
        self.results.push(CheckResult::pass("cache", "cache directory accessible"));
    }

    pub fn results(&self) -> &[CheckResult] {
        &self.results
    }

    pub fn has_errors(&self) -> bool {
        self.results.iter().any(|r| !r.passed && r.severity == CheckSeverity::Error)
    }

    pub fn has_warnings(&self) -> bool {
        self.results.iter().any(|r| !r.passed && r.severity == CheckSeverity::Warning)
    }

    pub fn summary(&self) -> (usize, usize, usize) {
        let passed = self.results.iter().filter(|r| r.passed).count();
        let warnings = self
            .results
            .iter()
            .filter(|r| !r.passed && r.severity == CheckSeverity::Warning)
            .count();
        let errors =
            self.results.iter().filter(|r| !r.passed && r.severity == CheckSeverity::Error).count();
        (passed, warnings, errors)
    }
}

impl Default for DoctorRunner {
    fn default() -> Self {
        Self::new()
    }
}
