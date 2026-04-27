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

use crate::arch::x86_64::vga::Color;
use crate::log::*;
use crate::test::framework::TestResult;

pub(crate) fn test_severity_debug_variant() -> TestResult {
    let sev = Severity::Debug;
    if sev != Severity::Debug {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_info_variant() -> TestResult {
    let sev = Severity::Info;
    if sev != Severity::Info {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_warn_variant() -> TestResult {
    let sev = Severity::Warn;
    if sev != Severity::Warn {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_err_variant() -> TestResult {
    let sev = Severity::Err;
    if sev != Severity::Err {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_fatal_variant() -> TestResult {
    let sev = Severity::Fatal;
    if sev != Severity::Fatal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_debug_color() -> TestResult {
    if Severity::Debug.color() != Color::Cyan {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_info_color() -> TestResult {
    if Severity::Info.color() != Color::LightGreen {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_warn_color() -> TestResult {
    if Severity::Warn.color() != Color::Yellow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_err_color() -> TestResult {
    if Severity::Err.color() != Color::LightRed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_fatal_color() -> TestResult {
    if Severity::Fatal.color() != Color::LightRed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_debug_as_str() -> TestResult {
    if Severity::Debug.as_str() != "DBG" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_info_as_str() -> TestResult {
    if Severity::Info.as_str() != "INFO" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_warn_as_str() -> TestResult {
    if Severity::Warn.as_str() != "WARN" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_err_as_str() -> TestResult {
    if Severity::Err.as_str() != "ERR" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_fatal_as_str() -> TestResult {
    if Severity::Fatal.as_str() != "FATAL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_clone() -> TestResult {
    let s1 = Severity::Info;
    let s2 = s1.clone();
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_copy() -> TestResult {
    let s1 = Severity::Warn;
    let s2 = s1;
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_equality() -> TestResult {
    if Severity::Debug != Severity::Debug {
        return TestResult::Fail;
    }
    if Severity::Info != Severity::Info {
        return TestResult::Fail;
    }
    if Severity::Warn != Severity::Warn {
        return TestResult::Fail;
    }
    if Severity::Err != Severity::Err {
        return TestResult::Fail;
    }
    if Severity::Fatal != Severity::Fatal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_inequality() -> TestResult {
    if Severity::Debug == Severity::Info {
        return TestResult::Fail;
    }
    if Severity::Info == Severity::Warn {
        return TestResult::Fail;
    }
    if Severity::Warn == Severity::Err {
        return TestResult::Fail;
    }
    if Severity::Err == Severity::Fatal {
        return TestResult::Fail;
    }
    if Severity::Fatal == Severity::Debug {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_debug_format() -> TestResult {
    let debug_str = alloc::format!("{:?}", Severity::Debug);
    if !debug_str.contains("Debug") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_info_debug_format() -> TestResult {
    let debug_str = alloc::format!("{:?}", Severity::Info);
    if !debug_str.contains("Info") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_warn_debug_format() -> TestResult {
    let debug_str = alloc::format!("{:?}", Severity::Warn);
    if !debug_str.contains("Warn") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_err_debug_format() -> TestResult {
    let debug_str = alloc::format!("{:?}", Severity::Err);
    if !debug_str.contains("Err") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_fatal_debug_format() -> TestResult {
    let debug_str = alloc::format!("{:?}", Severity::Fatal);
    if !debug_str.contains("Fatal") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_severity_variants_unique() -> TestResult {
    let severities =
        [Severity::Debug, Severity::Info, Severity::Warn, Severity::Err, Severity::Fatal];
    for i in 0..severities.len() {
        for j in (i + 1)..severities.len() {
            if severities[i] == severities[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_severity_str_representations_unique() -> TestResult {
    let strs = [
        Severity::Debug.as_str(),
        Severity::Info.as_str(),
        Severity::Warn.as_str(),
        Severity::Err.as_str(),
        Severity::Fatal.as_str(),
    ];
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            if strs[i] == strs[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_severity_color_returns_valid_color() -> TestResult {
    let severities =
        [Severity::Debug, Severity::Info, Severity::Warn, Severity::Err, Severity::Fatal];
    for sev in severities {
        let _ = sev.color();
    }
    TestResult::Pass
}

pub(crate) fn test_severity_as_str_not_empty() -> TestResult {
    let severities =
        [Severity::Debug, Severity::Info, Severity::Warn, Severity::Err, Severity::Fatal];
    for sev in severities {
        if sev.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_severity_err_and_fatal_same_color() -> TestResult {
    if Severity::Err.color() != Severity::Fatal.color() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_severity_debug_info_warn_different_colors() -> TestResult {
    if Severity::Debug.color() == Severity::Info.color() {
        return TestResult::Fail;
    }
    if Severity::Info.color() == Severity::Warn.color() {
        return TestResult::Fail;
    }
    if Severity::Debug.color() == Severity::Warn.color() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
