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

// Module load, unload, and policy enforcement.
//
// A legacy loader still lives at `crate::modules::nonos_module_loader`,
// only because the admin module-load syscall in
// `src/syscall/dispatch/hardware/admin.rs:98` hasn't been moved here yet.
// That loader has a zero-key signature placeholder — see its module
// comment for the specifics. The migration belongs to Wave 6 and needs a
// real trust anchor before it can land.

extern crate alloc;

pub mod constants;
pub mod error;
pub mod orchestrator;
pub mod types;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{LoaderError, LoaderResult};
pub use orchestrator::{init_loader, load_module, load_with_policy, unload_module};
pub use types::{LoaderPolicy, LoaderRequest};
