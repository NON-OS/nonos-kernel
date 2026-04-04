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

mod constants;
mod types;
mod state;
mod percpu_queue;
mod tick;
mod balance;
mod spawn;
mod api;

pub use constants::{MAX_CPUS, DEFAULT_TIME_SLICE, LOAD_BALANCE_INTERVAL_TICKS};
pub use types::{CpuRunQueueStats, CpuLoad, LoadBalanceState};
pub use state::{init_cpu_queue, get_cpu_queue, active_cpu_count, is_smp_initialized, for_each_cpu_queue};
pub use percpu_queue::PerCpuRunQueue;
pub use tick::smp_tick;
pub use balance::try_load_balance;
pub use spawn::{spawn_smp, spawn_on_cpu, run_local};
pub use api::*;
