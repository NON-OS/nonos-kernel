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

pub mod task;
pub mod runqueue;
pub mod context;
pub mod executor;
pub mod realtime;
pub mod scheduler;
mod api;

pub use scheduler::{
    init, get, spawn, run, tick, wakeup, enter,
    add_to_run_queue, remove_from_run_queue, is_in_run_queue,
    runnable_process_count, get_runnable_pids, get_scheduler_stats,
    SchedulerStatsSnapshot, sleep_until, wake_process, is_sleeping,
    get_remaining_sleep, yield_now,
};

pub use api::{current_scheduler, yield_cpu, schedule, current_cpu_id};
pub use task::{Task, Priority, CpuAffinity};
pub use runqueue::RunQueue;
pub use context::Context;
pub use executor::{spawn_async, poll_async_tasks, pending_async_tasks};
pub use realtime::{
    init as realtime_init, spawn_realtime, run_realtime_tasks,
    pending_realtime_tasks, has_realtime_tasks,
};
