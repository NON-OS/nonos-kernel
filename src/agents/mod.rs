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

pub mod context;
pub mod core;
pub mod executor;
pub mod llm;
pub mod memory;
pub mod presets;
pub mod registry;
pub mod scheduler;
pub mod tasks;
pub mod tools;

#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
pub mod tests;

pub use core::{Agent, AgentConfig};
pub use executor::{agent_output, current_agent, is_running, run_agent, stop_agent};
pub use presets::list_presets;
pub use registry::{create_agent, delete_agent, get_agent, list_agents};
pub use tools::{execute_tool, list_tools, register_tool};

pub fn init() {
    tools::init_builtin_tools();
}
