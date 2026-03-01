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

mod state;
mod policy;
mod context;
mod core;
mod spawn;
mod query;
mod config;
mod stats;

pub use policy::SchedulerPolicy;
pub use stats::{TaskStats, SchedulerStats, context_switch_count, set_time_quantum_us, get_time_quantum_us, get_task_stats, get_scheduler_stats, get_task_info_extended};
pub use core::{init, schedule, yield_now};
pub use spawn::{spawn, exit, sleep_ms};
pub use query::{current_id, task_count, is_init, get_task_info, for_each_task};
pub use config::{get_policy, set_policy, set_task_priority, get_task_priority, check_preempt, timer_tick};
