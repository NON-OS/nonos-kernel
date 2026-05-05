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

pub mod caps;
pub mod exec;
pub mod format;
pub mod loader;
pub mod manifest;
pub mod metrics;
pub mod registry;
pub mod sandbox;
pub mod signing;
pub mod types;
pub mod verify;

// Capsule download and lifecycle hooks are not on the microkernel
// trusted path. The trusted-path capsule load goes through
// `capsule::loader::load(data, token)` directly with bytes already in
// memory (`include_bytes!`); no network fetch, no on-chain marketplace,
// no in-kernel restart-policy state.

pub use caps::*;
pub use format::*;
pub use loader::*;
pub use manifest::*;
pub use registry::*;
pub use sandbox::*;
pub use types::*;
pub use verify::*;

// Microkernel capsule init: registry, loader, metrics, signing keys.
// No download cache (no network), no lifecycle restart hooks (capsules
// own their own liveness via `state::is_alive`).
