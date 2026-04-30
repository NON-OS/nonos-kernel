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

// MigrationOnly (Phase 1): this subtree is the cleanest first slice that
// lifts into the canonical winner `src/process/scheduler` during Wave 2 of
// the kernel core rebuild. The PID run queue, sleep table, and wakeup hook
// here already speak to `crate::process::nonos_core::PROCESS_TABLE`; only
// the namespace is wrong. No new code, no new exports, no new state.
// See PHASE_1_KILL_LIST_AND_FREEZE_PLAN.md and CANONICAL_SUBSYSTEM_WINNER_MAP.md.

mod run_queue;
mod sleep;
mod wakeup;

pub use run_queue::{add_to_run_queue, is_in_run_queue, remove_from_run_queue};
pub use run_queue::{get_runnable_pids, runnable_process_count};
pub use sleep::{
    check_sleeping_processes, get_remaining_sleep, is_sleeping, sleep_until, wake_process,
};
pub use wakeup::wakeup;
