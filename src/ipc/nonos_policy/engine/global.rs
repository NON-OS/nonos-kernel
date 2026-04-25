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

use super::policy::IpcPolicy;
use crate::ipc::nonos_policy::module_policy::ModulePolicy;

static POLICY_INSTANCE: IpcPolicy = IpcPolicy::new();

#[inline]
pub fn get_policy() -> &'static IpcPolicy {
    &POLICY_INSTANCE
}

pub static ACTIVE_POLICY: &IpcPolicy = &POLICY_INSTANCE;

pub fn init_default_policies() {
    let policy = get_policy();
    policy.register_module("kernel", ModulePolicy::kernel());
    policy.register_module("scheduler", ModulePolicy::kernel());
    policy.register_module("memory", ModulePolicy::kernel());
    policy.register_module("security", ModulePolicy::kernel());
    policy.register_module("crypto", ModulePolicy::kernel());
    policy.register_module("filesystem", ModulePolicy::kernel());
    policy.register_module("network", ModulePolicy::kernel());
    policy.register_module("capability_validator", ModulePolicy::kernel());
    policy.require_encryption("*", "security");
    policy.require_encryption("*", "crypto");
    policy.require_encryption("*", "vault");
}
