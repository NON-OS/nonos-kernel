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

mod api;
pub mod auth;
pub mod loader;
pub mod manifest;
pub mod mod_loader;
pub mod registry;
pub mod runner;
pub mod sandbox;

pub mod nonos_auth;
pub mod nonos_loader;
pub mod nonos_manifest;
pub mod nonos_mod_runner;
pub mod nonos_module_loader;
pub mod nonos_registry;
pub mod nonos_sandbox;

pub use api::register_active_module;
pub use auth::{
    authenticate_module, erase_auth_context, verify_signature, AuthContext, AuthError, AuthMethod,
    AuthResult,
};
pub use loader::{
    init_loader, load_module, load_with_policy, unload_module, LoaderError, LoaderPolicy,
    LoaderRequest, LoaderResult,
};
pub use manifest::{
    AttestationEntry, ManifestBuilder, ManifestError, ManifestResult, MemoryRequirements,
    ModuleManifest, ModuleType, PrivacyPolicy,
};
pub use registry::{
    get_module_by_id, get_module_entry, get_module_info, is_module_active, list_modules,
    module_count, register_module, set_module_state, set_module_state_by_name, unregister_module,
    ModuleInfo, ModuleState, RegistryError, RegistryResult, ACTIVE_MODULES,
};
pub use runner::{
    check_watchdogs, get_module_state, get_running_count, handle_module_fault, heartbeat,
    init_executor, is_executor_ready, pause_module, restart_module, resume_module, start_module,
    start_module_with_config, stop_module, terminate_all_modules, ExecutionContext, ExecutionState,
    FaultInfo, FaultPolicy, FaultType, RunnerConfig, RunnerError, RunnerResult,
};
pub use sandbox::{
    destroy_sandbox, setup_sandbox, SandboxConfig, SandboxError, SandboxResult, SandboxState,
};

pub fn get_module(name: &str) -> Option<ModuleInfo> {
    get_module_info(name).ok()
}

#[cfg(test)]
mod tests;
