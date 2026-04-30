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

// Module isolation and capability semantics.
//
// One thing worth flagging for whoever extends this: vault and key custody
// don't belong in a sandbox. The deleted legacy sibling carried a `crypto`
// submodule that generated quantum keys here — a layering mistake. Don't
// reintroduce that pattern; key material lives under `src/vault`.

extern crate alloc;

pub mod constants;
pub mod error;
pub mod manager;
pub mod types;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{SandboxError, SandboxResult};
pub use manager::{
    destroy_sandbox, get_sandbox_memory, is_sandbox_active, list_active_sandboxes,
    sandbox_has_capability, setup_sandbox,
};
pub use types::{SandboxConfig, SandboxState};
