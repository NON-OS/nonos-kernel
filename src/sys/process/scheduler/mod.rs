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

mod config;
mod context;
mod core;
mod policy;
mod query;
mod spawn;
mod state;
mod stats;

pub use config::{
    check_preempt, get_policy, get_task_priority, set_policy, set_task_priority, timer_tick,
};
pub use core::{init, schedule, yield_now};
pub use policy::SchedulerPolicy;
pub use query::{current_id, for_each_task, get_task_info, is_init, task_count};
pub use spawn::{exit, sleep_ms, spawn};
pub use stats::{
    context_switch_count, get_scheduler_stats, get_task_info_extended, get_task_stats,
    get_time_quantum_us, set_time_quantum_us, SchedulerStats, TaskStats,
};
