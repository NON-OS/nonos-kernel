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

mod types;
mod waker;
mod queue;
mod state;
mod task;
mod spawn;
mod poll;
mod stats;

pub use types::{AsyncTask, AsyncTaskPriority, ExecutorStatsSnapshot};
pub use spawn::{spawn_async, spawn_async_with_priority};
pub use poll::{poll_async_tasks, poll_async_tasks_limited, poll_critical_tasks};
pub use stats::{pending_async_tasks, total_async_tasks, get_executor_stats, has_woken_tasks};
pub use waker::wake_task;
