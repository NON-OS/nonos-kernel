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

// FROZEN: DUPLICATE AUTHORITY (Phase 1, discovered outside published kill list).
// This subtree is a third parallel scheduler/task universe alongside the
// frozen `src/sched` shim and the canonical winner `src/process/scheduler`.
// It owns its own `Task`, `TaskState`, `CpuContext`, `SchedulerPolicy`,
// `MAX_TASKS`, `TASK_STACK_SIZE`, full lifecycle (init/spawn/exit/sleep/yield),
// and a parallel stats surface. Constitutional violation: one authority per
// domain. No new code, no new exports, no new state. End state: deletion
// after the two remaining consumers migrate to canonical APIs.
// Confirmed external consumers (crate-wide):
//   - src/shell/commands/processes/info.rs::cmd_top (uses is_init,
//     for_each_task, state_str, TaskState)
//   - src/sys/tests/process_tests.rs (frozen test surface)
// See PHASE_1_KILL_LIST_AND_FREEZE_PLAN.md.

mod scheduler;
mod types;

pub use scheduler::{
    context_switch_count, current_id, for_each_task, get_policy, get_scheduler_stats,
    get_task_info, get_task_info_extended, get_task_priority, get_task_stats,
    get_time_quantum_us, init, is_init, set_policy, set_time_quantum_us, task_count,
    SchedulerPolicy, SchedulerStats, TaskStats,
};
pub use types::{state_str, CpuContext, Task, TaskState, MAX_TASKS, TASK_STACK_SIZE};
