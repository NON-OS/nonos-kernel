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
mod core;
mod preemption;
mod selection;
mod process;
mod stats;
mod module_tasks;

pub use types::{Scheduler, SchedulerStatsSnapshot, ModuleTaskError, ModuleTaskResult};
pub use core::{init, get, spawn, run, enter};
pub use preemption::{tick, yield_now, need_reschedule, clear_reschedule};
pub use process::{
    sleep_until, wake_process, is_sleeping, get_remaining_sleep,
    add_to_run_queue, remove_from_run_queue, is_in_run_queue,
    runnable_process_count, get_runnable_pids, wakeup,
};
pub use stats::get_scheduler_stats;
pub use module_tasks::{
    spawn_module_task, terminate_module_tasks,
    has_running_tasks, force_kill_module_tasks,
};
