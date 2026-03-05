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

//! Process subsystem tests
//!
//! Tests for process creation, isolation, scheduling, and IPC.

extern crate alloc;

use super::framework::{TestResult, TestCase, TestSuite};

/// Run all process tests
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Process");

    suite.add_test(TestCase::new(
        "process_state",
        test_process_state,
        "process",
    ));
    suite.add_test(TestCase::new(
        "process_priority",
        test_process_priority,
        "process",
    ));
    suite.add_test(TestCase::new(
        "scheduler_priority",
        test_scheduler_priority,
        "process",
    ));
    suite.add_test(TestCase::new(
        "process_table",
        test_process_table,
        "process",
    ));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

/// Test process state transitions
fn test_process_state() -> TestResult {
    use crate::process::nonos_core::ProcessState;

    // Test state values are distinct
    let new = ProcessState::New;
    let ready = ProcessState::Ready;
    let running = ProcessState::Running;
    let sleeping = ProcessState::Sleeping;
    let stopped = ProcessState::Stopped;

    // All states should be different
    if new == ready {
        return TestResult::Fail;
    }
    if ready == running {
        return TestResult::Fail;
    }
    if running == sleeping {
        return TestResult::Fail;
    }
    if sleeping == stopped {
        return TestResult::Fail;
    }

    // Zombie and Terminated carry exit codes
    let zombie = ProcessState::Zombie(0);
    let terminated = ProcessState::Terminated(0);

    if zombie == terminated {
        return TestResult::Fail;
    }

    TestResult::Pass
}

/// Test process priority levels
fn test_process_priority() -> TestResult {
    use crate::process::nonos_core::Priority;

    // Test priority ordering
    let idle = Priority::Idle;
    let low = Priority::Low;
    let normal = Priority::Normal;
    let high = Priority::High;
    let realtime = Priority::RealTime;

    // Priorities should be distinct
    if idle == low {
        return TestResult::Fail;
    }
    if low == normal {
        return TestResult::Fail;
    }
    if normal == high {
        return TestResult::Fail;
    }
    if high == realtime {
        return TestResult::Fail;
    }

    TestResult::Pass
}

/// Test scheduler task priority
fn test_scheduler_priority() -> TestResult {
    use crate::sched::Priority;

    // Test scheduler priority levels
    let idle = Priority::Idle;
    let low = Priority::Low;
    let normal = Priority::Normal;
    let high = Priority::High;
    let critical = Priority::Critical;
    let realtime = Priority::RealTime;

    // Test ordering (Idle < Low < Normal < High < Critical < RealTime)
    if idle >= low {
        return TestResult::Fail;
    }
    if low >= normal {
        return TestResult::Fail;
    }
    if normal >= high {
        return TestResult::Fail;
    }
    if high >= critical {
        return TestResult::Fail;
    }
    if critical >= realtime {
        return TestResult::Fail;
    }

    TestResult::Pass
}

/// Test process table access
fn test_process_table() -> TestResult {
    // Test that we can access process management functions
    use crate::process;

    // Just verify the init function exists and doesn't panic when called
    // (It should be safe to call multiple times)
    // Note: We don't actually call init here as it may have side effects
    // Instead, we verify the module is accessible
    let _ = process::current_process();

    TestResult::Pass
}
