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

// Application model — context, lifecycle, registry, types. The
// registry/runtime/manifest authority that `src/sdk` currently still
// exposes is a developer-API holdover from before the split; that
// ownership migrates here in Wave 5, and the SDK survives only as a
// client-facing layer afterwards.

extern crate alloc;

pub mod context;
pub mod ecosystem;
pub mod lifecycle;
pub mod registry;
pub mod types;

pub use context::{AppContext, AppPermissions, PermissionLevel};
pub use lifecycle::{resume_app, start_app, stop_app, suspend_app, AppEvent, LifecycleState};
pub use registry::{get_app, list_apps, register_app, unregister_app, AppEntry, AppInfo};
pub use types::{AppError, AppId, AppResult, AppType};

#[cfg(test)]
mod tests;
