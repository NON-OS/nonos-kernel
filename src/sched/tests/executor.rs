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

use crate::sched::executor::*;
use crate::test::framework::TestResult;

pub(crate) fn test_async_task_priority_values() -> TestResult {
    if AsyncTaskPriority::Critical as u8 != 0 {
        return TestResult::Fail;
    }
    if AsyncTaskPriority::High as u8 != 1 {
        return TestResult::Fail;
    }
    if AsyncTaskPriority::Normal as u8 != 2 {
        return TestResult::Fail;
    }
    if AsyncTaskPriority::Low as u8 != 3 {
        return TestResult::Fail;
    }
    if AsyncTaskPriority::Idle as u8 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_ordering() -> TestResult {
    if !(AsyncTaskPriority::Critical < AsyncTaskPriority::High) {
        return TestResult::Fail;
    }
    if !(AsyncTaskPriority::High < AsyncTaskPriority::Normal) {
        return TestResult::Fail;
    }
    if !(AsyncTaskPriority::Normal < AsyncTaskPriority::Low) {
        return TestResult::Fail;
    }
    if !(AsyncTaskPriority::Low < AsyncTaskPriority::Idle) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_default() -> TestResult {
    let priority: AsyncTaskPriority = Default::default();
    if priority != AsyncTaskPriority::Normal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_clone() -> TestResult {
    let p1 = AsyncTaskPriority::High;
    let p2 = p1.clone();
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_copy() -> TestResult {
    let p1 = AsyncTaskPriority::Critical;
    let p2 = p1;
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_equality() -> TestResult {
    if AsyncTaskPriority::Normal != AsyncTaskPriority::Normal {
        return TestResult::Fail;
    }
    if AsyncTaskPriority::High == AsyncTaskPriority::Low {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_debug() -> TestResult {
    let debug_str = alloc::format!("{:?}", AsyncTaskPriority::Critical);
    if !debug_str.contains("Critical") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_partial_ord() -> TestResult {
    if !(AsyncTaskPriority::Critical <= AsyncTaskPriority::High) {
        return TestResult::Fail;
    }
    if !(AsyncTaskPriority::Idle >= AsyncTaskPriority::Low) {
        return TestResult::Fail;
    }
    if !(AsyncTaskPriority::Normal <= AsyncTaskPriority::Normal) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_ord_sort() -> TestResult {
    let mut priorities = [
        AsyncTaskPriority::Low,
        AsyncTaskPriority::Critical,
        AsyncTaskPriority::Idle,
        AsyncTaskPriority::High,
        AsyncTaskPriority::Normal,
    ];
    priorities.sort();
    if priorities[0] != AsyncTaskPriority::Critical {
        return TestResult::Fail;
    }
    if priorities[1] != AsyncTaskPriority::High {
        return TestResult::Fail;
    }
    if priorities[2] != AsyncTaskPriority::Normal {
        return TestResult::Fail;
    }
    if priorities[3] != AsyncTaskPriority::Low {
        return TestResult::Fail;
    }
    if priorities[4] != AsyncTaskPriority::Idle {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_executor_stats_snapshot_default_values() -> TestResult {
    let stats = ExecutorStatsSnapshot {
        tasks_spawned: 0,
        tasks_completed: 0,
        polls_performed: 0,
        wakeups_triggered: 0,
        pending_tasks: 0,
        woken_tasks: 0,
    };
    if stats.tasks_spawned != 0 {
        return TestResult::Fail;
    }
    if stats.tasks_completed != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_executor_stats_snapshot_with_values() -> TestResult {
    let stats = ExecutorStatsSnapshot {
        tasks_spawned: 100,
        tasks_completed: 50,
        polls_performed: 200,
        wakeups_triggered: 75,
        pending_tasks: 25,
        woken_tasks: 10,
    };
    if stats.tasks_spawned != 100 {
        return TestResult::Fail;
    }
    if stats.tasks_completed != 50 {
        return TestResult::Fail;
    }
    if stats.polls_performed != 200 {
        return TestResult::Fail;
    }
    if stats.wakeups_triggered != 75 {
        return TestResult::Fail;
    }
    if stats.pending_tasks != 25 {
        return TestResult::Fail;
    }
    if stats.woken_tasks != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_executor_stats_snapshot_clone() -> TestResult {
    let stats1 = ExecutorStatsSnapshot {
        tasks_spawned: 42,
        tasks_completed: 21,
        polls_performed: 84,
        wakeups_triggered: 10,
        pending_tasks: 5,
        woken_tasks: 3,
    };
    let stats2 = stats1.clone();
    if stats1.tasks_spawned != stats2.tasks_spawned {
        return TestResult::Fail;
    }
    if stats1.tasks_completed != stats2.tasks_completed {
        return TestResult::Fail;
    }
    if stats1.polls_performed != stats2.polls_performed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_executor_stats_snapshot_debug() -> TestResult {
    let stats = ExecutorStatsSnapshot {
        tasks_spawned: 1,
        tasks_completed: 0,
        polls_performed: 1,
        wakeups_triggered: 0,
        pending_tasks: 1,
        woken_tasks: 0,
    };
    let debug_str = alloc::format!("{:?}", stats);
    if !debug_str.contains("ExecutorStatsSnapshot") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_async_task_priority_variants_unique() -> TestResult {
    let priorities = [
        AsyncTaskPriority::Critical,
        AsyncTaskPriority::High,
        AsyncTaskPriority::Normal,
        AsyncTaskPriority::Low,
        AsyncTaskPriority::Idle,
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

pub(crate) fn test_async_task_priority_is_ord() -> TestResult {
    fn is_ord<T: Ord>() {}
    is_ord::<AsyncTaskPriority>();
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_is_partial_ord() -> TestResult {
    fn is_partial_ord<T: PartialOrd>() {}
    is_partial_ord::<AsyncTaskPriority>();
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_is_eq() -> TestResult {
    fn is_eq<T: Eq>() {}
    is_eq::<AsyncTaskPriority>();
    TestResult::Pass
}

pub(crate) fn test_async_task_priority_is_partial_eq() -> TestResult {
    fn is_partial_eq<T: PartialEq>() {}
    is_partial_eq::<AsyncTaskPriority>();
    TestResult::Pass
}

pub(crate) fn test_executor_stats_snapshot_is_clone() -> TestResult {
    fn is_clone<T: Clone>() {}
    is_clone::<ExecutorStatsSnapshot>();
    TestResult::Pass
}

pub(crate) fn test_executor_stats_snapshot_is_debug() -> TestResult {
    fn is_debug<T: core::fmt::Debug>() {}
    is_debug::<ExecutorStatsSnapshot>();
    TestResult::Pass
}
