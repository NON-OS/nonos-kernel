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

extern crate alloc;

pub mod auth;
pub mod loader;
pub mod manifest;
pub mod mod_loader;
pub mod registry;
pub mod runner;
pub mod sandbox;
mod api;

pub mod nonos_module_loader;
pub mod nonos_auth;
pub mod nonos_loader;
pub mod nonos_manifest;
pub mod nonos_mod_runner;
pub mod nonos_registry;
pub mod nonos_sandbox;

pub use auth::{AuthContext, AuthMethod, AuthError, AuthResult, authenticate_module, verify_signature, erase_auth_context};
pub use loader::{LoaderError, LoaderResult, LoaderPolicy, LoaderRequest, load_module, load_with_policy, unload_module, init_loader};
pub use manifest::{ModuleManifest, ModuleType, PrivacyPolicy, MemoryRequirements, AttestationEntry, ManifestError, ManifestResult, ManifestBuilder};
pub use registry::{ModuleInfo, ModuleState, RegistryError, RegistryResult, ACTIVE_MODULES, register_module, unregister_module, is_module_active, get_module_info, get_module_by_id, list_modules, set_module_state_by_name, module_count, set_module_state, get_module_entry};
pub use runner::{ExecutionContext, ExecutionState, FaultInfo, FaultPolicy, FaultType, RunnerConfig, RunnerError, RunnerResult, init_executor, is_executor_ready, start_module, start_module_with_config, stop_module, pause_module, resume_module, handle_module_fault, restart_module, get_module_state, get_running_count, heartbeat, check_watchdogs, terminate_all_modules};
pub use sandbox::{SandboxConfig, SandboxState, SandboxError, SandboxResult, setup_sandbox, destroy_sandbox};
pub use api::register_active_module;
