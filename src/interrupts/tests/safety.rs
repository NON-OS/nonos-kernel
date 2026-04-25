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

use crate::interrupts::*;
use crate::test::framework::TestResult;

pub(crate) fn test_in_interrupt_context_returns_bool() -> TestResult {
    let in_ctx = in_interrupt_context();
    if !(in_ctx == true || in_ctx == false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_interrupt_context_creates_context() -> TestResult {
    let _ctx = set_interrupt_context();
    if !in_interrupt_context() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interrupt_context_cleared_on_drop() -> TestResult {
    {
        let _ctx = set_interrupt_context();
        if !in_interrupt_context() {
            return TestResult::Fail;
        }
    }
    if in_interrupt_context() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nested_interrupt_context() -> TestResult {
    {
        let _ctx1 = set_interrupt_context();
        if !in_interrupt_context() {
            return TestResult::Fail;
        }
        {
            let _ctx2 = set_interrupt_context();
            if !in_interrupt_context() {
                return TestResult::Fail;
            }
        }
        if !in_interrupt_context() {
            return TestResult::Fail;
        }
    }
    if in_interrupt_context() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_disable_interrupts_guard_returns_guard() -> TestResult {
    let _guard = disable_interrupts_guard();
    TestResult::Pass
}

pub(crate) fn test_interrupt_guard_restores_on_drop() -> TestResult {
    {
        let _guard = disable_interrupts_guard();
    }
    TestResult::Pass
}

pub(crate) fn test_nested_interrupt_guards() -> TestResult {
    {
        let _guard1 = disable_interrupts_guard();
        {
            let _guard2 = disable_interrupts_guard();
        }
    }
    TestResult::Pass
}

pub(crate) fn test_interrupt_context_multiple_drops() -> TestResult {
    let ctx1 = set_interrupt_context();
    let ctx2 = set_interrupt_context();
    if !in_interrupt_context() {
        return TestResult::Fail;
    }
    drop(ctx2);
    if !in_interrupt_context() {
        return TestResult::Fail;
    }
    drop(ctx1);
    if in_interrupt_context() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interrupt_guard_and_context_together() -> TestResult {
    let _guard = disable_interrupts_guard();
    let _ctx = set_interrupt_context();
    if !in_interrupt_context() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
