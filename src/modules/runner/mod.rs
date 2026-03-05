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

pub mod constants;
pub mod error;
pub mod context;
pub mod types;
pub mod helpers;
pub mod executor;
pub mod watchdog;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{RunnerError, RunnerResult};
pub use types::{ExecutionContext, ExecutionState, FaultInfo, FaultPolicy, FaultType, RunnerConfig};
pub use executor::{
    init_executor,
    is_executor_ready,
    start_module,
    start_module_with_config,
    stop_module,
    pause_module,
    resume_module,
    handle_module_fault,
    restart_module,
    get_module_state,
};
pub use watchdog::{get_running_count, heartbeat, check_watchdogs, terminate_all_modules};
