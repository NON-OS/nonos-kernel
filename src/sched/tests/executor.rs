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

#[test]
fn test_async_task_priority_values() {
    assert_eq!(AsyncTaskPriority::Critical as u8, 0);
    assert_eq!(AsyncTaskPriority::High as u8, 1);
    assert_eq!(AsyncTaskPriority::Normal as u8, 2);
    assert_eq!(AsyncTaskPriority::Low as u8, 3);
    assert_eq!(AsyncTaskPriority::Idle as u8, 4);
}

#[test]
fn test_async_task_priority_ordering() {
    assert!(AsyncTaskPriority::Critical < AsyncTaskPriority::High);
    assert!(AsyncTaskPriority::High < AsyncTaskPriority::Normal);
    assert!(AsyncTaskPriority::Normal < AsyncTaskPriority::Low);
    assert!(AsyncTaskPriority::Low < AsyncTaskPriority::Idle);
}

#[test]
fn test_async_task_priority_default() {
    let priority: AsyncTaskPriority = Default::default();
    assert_eq!(priority, AsyncTaskPriority::Normal);
}

#[test]
fn test_async_task_priority_clone() {
    let p1 = AsyncTaskPriority::High;
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn test_async_task_priority_copy() {
    let p1 = AsyncTaskPriority::Critical;
    let p2 = p1;
    assert_eq!(p1, p2);
}

#[test]
fn test_async_task_priority_equality() {
    assert_eq!(AsyncTaskPriority::Normal, AsyncTaskPriority::Normal);
    assert_ne!(AsyncTaskPriority::High, AsyncTaskPriority::Low);
}

#[test]
fn test_async_task_priority_debug() {
    let debug_str = alloc::format!("{:?}", AsyncTaskPriority::Critical);
    assert!(debug_str.contains("Critical"));
}

#[test]
fn test_async_task_priority_partial_ord() {
    assert!(AsyncTaskPriority::Critical <= AsyncTaskPriority::High);
    assert!(AsyncTaskPriority::Idle >= AsyncTaskPriority::Low);
    assert!(AsyncTaskPriority::Normal <= AsyncTaskPriority::Normal);
}

#[test]
fn test_async_task_priority_ord_sort() {
    let mut priorities = [
        AsyncTaskPriority::Low,
        AsyncTaskPriority::Critical,
        AsyncTaskPriority::Idle,
        AsyncTaskPriority::High,
        AsyncTaskPriority::Normal,
    ];
    priorities.sort();
    assert_eq!(priorities[0], AsyncTaskPriority::Critical);
    assert_eq!(priorities[1], AsyncTaskPriority::High);
    assert_eq!(priorities[2], AsyncTaskPriority::Normal);
    assert_eq!(priorities[3], AsyncTaskPriority::Low);
    assert_eq!(priorities[4], AsyncTaskPriority::Idle);
}

#[test]
fn test_executor_stats_snapshot_default_values() {
    let stats = ExecutorStatsSnapshot {
        tasks_spawned: 0,
        tasks_completed: 0,
        polls_performed: 0,
        wakeups_triggered: 0,
        pending_tasks: 0,
        woken_tasks: 0,
    };
    assert_eq!(stats.tasks_spawned, 0);
    assert_eq!(stats.tasks_completed, 0);
}

#[test]
fn test_executor_stats_snapshot_with_values() {
    let stats = ExecutorStatsSnapshot {
        tasks_spawned: 100,
        tasks_completed: 50,
        polls_performed: 200,
        wakeups_triggered: 75,
        pending_tasks: 25,
        woken_tasks: 10,
    };
    assert_eq!(stats.tasks_spawned, 100);
    assert_eq!(stats.tasks_completed, 50);
    assert_eq!(stats.polls_performed, 200);
    assert_eq!(stats.wakeups_triggered, 75);
    assert_eq!(stats.pending_tasks, 25);
    assert_eq!(stats.woken_tasks, 10);
}

#[test]
fn test_executor_stats_snapshot_clone() {
    let stats1 = ExecutorStatsSnapshot {
        tasks_spawned: 42,
        tasks_completed: 21,
        polls_performed: 84,
        wakeups_triggered: 10,
        pending_tasks: 5,
        woken_tasks: 3,
    };
    let stats2 = stats1.clone();
    assert_eq!(stats1.tasks_spawned, stats2.tasks_spawned);
    assert_eq!(stats1.tasks_completed, stats2.tasks_completed);
    assert_eq!(stats1.polls_performed, stats2.polls_performed);
}

#[test]
fn test_executor_stats_snapshot_debug() {
    let stats = ExecutorStatsSnapshot {
        tasks_spawned: 1,
        tasks_completed: 0,
        polls_performed: 1,
        wakeups_triggered: 0,
        pending_tasks: 1,
        woken_tasks: 0,
    };
    let debug_str = alloc::format!("{:?}", stats);
    assert!(debug_str.contains("ExecutorStatsSnapshot"));
}

#[test]
fn test_all_async_task_priority_variants_unique() {
    let priorities = [
        AsyncTaskPriority::Critical,
        AsyncTaskPriority::High,
        AsyncTaskPriority::Normal,
        AsyncTaskPriority::Low,
        AsyncTaskPriority::Idle,
    ];
    for i in 0..priorities.len() {
        for j in (i + 1)..priorities.len() {
            assert_ne!(priorities[i], priorities[j]);
        }
    }
}

#[test]
fn test_async_task_priority_is_ord() {
    fn is_ord<T: Ord>() {}
    is_ord::<AsyncTaskPriority>();
}

#[test]
fn test_async_task_priority_is_partial_ord() {
    fn is_partial_ord<T: PartialOrd>() {}
    is_partial_ord::<AsyncTaskPriority>();
}

#[test]
fn test_async_task_priority_is_eq() {
    fn is_eq<T: Eq>() {}
    is_eq::<AsyncTaskPriority>();
}

#[test]
fn test_async_task_priority_is_partial_eq() {
    fn is_partial_eq<T: PartialEq>() {}
    is_partial_eq::<AsyncTaskPriority>();
}

#[test]
fn test_executor_stats_snapshot_is_clone() {
    fn is_clone<T: Clone>() {}
    is_clone::<ExecutorStatsSnapshot>();
}

#[test]
fn test_executor_stats_snapshot_is_debug() {
    fn is_debug<T: core::fmt::Debug>() {}
    is_debug::<ExecutorStatsSnapshot>();
}
