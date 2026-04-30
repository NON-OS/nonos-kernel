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

// Module execution lifecycle.

pub mod constants;
pub mod context;
pub mod error;
pub mod executor;
pub mod helpers;
pub mod types;
pub mod watchdog;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{RunnerError, RunnerResult};
pub use executor::{
    get_module_state, handle_module_fault, init_executor, is_executor_ready, pause_module,
    restart_module, resume_module, start_module, start_module_with_config, stop_module,
};
pub use types::{
    ExecutionContext, ExecutionState, FaultInfo, FaultPolicy, FaultType, RunnerConfig,
};
pub use watchdog::{check_watchdogs, get_running_count, heartbeat, terminate_all_modules};
