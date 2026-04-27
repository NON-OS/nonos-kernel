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

use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckSeverity {
    Info,
    Warning,
    Error,
    Fatal,
}

#[derive(Clone, Debug)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub severity: CheckSeverity,
    pub message: String,
    pub fix_hint: Option<String>,
}

pub trait DoctorCheck {
    fn name(&self) -> &str;
    fn run(&self) -> CheckResult;
}

impl CheckResult {
    pub fn pass(name: &str, msg: &str) -> Self {
        Self {
            name: String::from(name),
            passed: true,
            severity: CheckSeverity::Info,
            message: String::from(msg),
            fix_hint: None,
        }
    }

    pub fn warn(name: &str, msg: &str, hint: Option<&str>) -> Self {
        Self {
            name: String::from(name),
            passed: false,
            severity: CheckSeverity::Warning,
            message: String::from(msg),
            fix_hint: hint.map(String::from),
        }
    }

    pub fn fail(name: &str, msg: &str, hint: Option<&str>) -> Self {
        Self {
            name: String::from(name),
            passed: false,
            severity: CheckSeverity::Error,
            message: String::from(msg),
            fix_hint: hint.map(String::from),
        }
    }
}
