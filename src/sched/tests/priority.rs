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

use crate::sched::*;
use crate::test::framework::TestResult;

pub(crate) fn test_priority_values() -> TestResult {
    if Priority::Idle as u8 != 0 {
        return TestResult::Fail;
    }
    if Priority::Low as u8 != 1 {
        return TestResult::Fail;
    }
    if Priority::Normal as u8 != 2 {
        return TestResult::Fail;
    }
    if Priority::High as u8 != 3 {
        return TestResult::Fail;
    }
    if Priority::Critical as u8 != 4 {
        return TestResult::Fail;
    }
    if Priority::RealTime as u8 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_priority_ordering() -> TestResult {
    if !(Priority::RealTime > Priority::Critical) {
        return TestResult::Fail;
    }
    if !(Priority::Critical > Priority::High) {
        return TestResult::Fail;
    }
    if !(Priority::High > Priority::Normal) {
        return TestResult::Fail;
    }
    if !(Priority::Normal > Priority::Low) {
        return TestResult::Fail;
    }
    if !(Priority::Low > Priority::Idle) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_priority_equality() -> TestResult {
    if Priority::Normal != Priority::Normal {
        return TestResult::Fail;
    }
    if Priority::High == Priority::Low {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_priority_clone() -> TestResult {
    let p1 = Priority::High;
    let p2 = p1.clone();
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_priority_copy() -> TestResult {
    let p1 = Priority::Critical;
    let p2 = p1;
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_priority_partial_ord() -> TestResult {
    if !(Priority::RealTime >= Priority::Critical) {
        return TestResult::Fail;
    }
    if !(Priority::Idle <= Priority::Low) {
        return TestResult::Fail;
    }
    if !(Priority::Normal <= Priority::Normal) {
        return TestResult::Fail;
    }
    if !(Priority::High >= Priority::High) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_priority_debug() -> TestResult {
    let debug_str = alloc::format!("{:?}", Priority::Normal);
    if !debug_str.contains("Normal") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_priority_variants_unique() -> TestResult {
    let priorities = [
        Priority::Idle,
        Priority::Low,
        Priority::Normal,
        Priority::High,
        Priority::Critical,
        Priority::RealTime,
    ];
    for i in 0..priorities.len() {
        for j in (i + 1)..priorities.len() {
            if priorities[i] == priorities[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_priority_ord_consistency() -> TestResult {
    let mut priorities = [
        Priority::High,
        Priority::Idle,
        Priority::RealTime,
        Priority::Normal,
        Priority::Low,
        Priority::Critical,
    ];
    priorities.sort();
    if priorities[0] != Priority::Idle {
        return TestResult::Fail;
    }
    if priorities[1] != Priority::Low {
        return TestResult::Fail;
    }
    if priorities[2] != Priority::Normal {
        return TestResult::Fail;
    }
    if priorities[3] != Priority::High {
        return TestResult::Fail;
    }
    if priorities[4] != Priority::Critical {
        return TestResult::Fail;
    }
    if priorities[5] != Priority::RealTime {
        return TestResult::Fail;
    }
    TestResult::Pass
}
