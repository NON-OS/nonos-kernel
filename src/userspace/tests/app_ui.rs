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

use crate::test::framework::TestResult;

const ABOUT_APP_SRC: &str = include_str!("../../../userland/capsule_about/src/main.rs");

pub(crate) fn test_about_app_exit_cleanup_markers() -> TestResult {
    if !ABOUT_APP_SRC.contains("mk_exit(0)") {
        return TestResult::Fail;
    }
    if !ABOUT_APP_SRC.contains("ipc parked") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_about_app_no_global_mut_state() -> TestResult {
    if ABOUT_APP_SRC.contains("static mut") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
