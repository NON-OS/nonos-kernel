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

use core::sync::atomic::Ordering;

use super::types::ExecutorStatsSnapshot;
use super::state::{ASYNC_QUEUE, WOKEN_TASKS, EXECUTOR_STATS};

pub fn pending_async_tasks() -> usize {
    ASYNC_QUEUE.lock().pending_count()
}

pub fn total_async_tasks() -> usize {
    ASYNC_QUEUE.lock().total_len()
}

pub fn get_executor_stats() -> ExecutorStatsSnapshot {
    ExecutorStatsSnapshot {
        tasks_spawned: EXECUTOR_STATS.tasks_spawned.load(Ordering::Relaxed),
        tasks_completed: EXECUTOR_STATS.tasks_completed.load(Ordering::Relaxed),
        polls_performed: EXECUTOR_STATS.polls_performed.load(Ordering::Relaxed),
        wakeups_triggered: EXECUTOR_STATS.wakeups_triggered.load(Ordering::Relaxed),
        pending_tasks: pending_async_tasks(),
        woken_tasks: WOKEN_TASKS.read().len(),
    }
}

pub fn has_woken_tasks() -> bool {
    !WOKEN_TASKS.read().is_empty()
}
