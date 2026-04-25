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

mod capability;
mod engine;
mod error;
mod module_policy;
mod violation;

pub use capability::IpcCapability;
pub use engine::{
    get_policy, init_default_policies, IpcPolicy, PolicyStatsSnapshot, ACTIVE_POLICY,
};
pub use error::PolicyError;
pub use module_policy::ModulePolicy;
pub use violation::PolicyViolation;
