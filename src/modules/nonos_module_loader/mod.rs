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

// Legacy module loader. The canonical loader is `src/modules/loader`. This
// tree only still exists because the admin module-load syscall in
// `src/syscall/dispatch/hardware/admin.rs:98` routes through
// `NONOS_MODULE_LOADER.load_module(...)` here. The four intra-cluster
// callers were already deleted in Wave 2; the syscall is the last thread
// holding this on disk.
//
// The trust path here is broken in ways the canonical loader must not
// inherit. Wave 6 needs to read these carefully before migrating the
// syscall onto the canonical loader:
//
//   - `manager.rs:63` calls
//     `crate::crypto::ed25519::verify(&[0u8; 32], &hash, &sig)`. The
//     "trust anchor" is a literal zero pubkey, so every signature passes.
//     This is the worst flag in the repo and the reason this tree must
//     not be reused for anything trust-shaped.
//   - `manager.rs:57` only runs verification under
//     `!cfg!(feature = "std")`. Std builds skip it silently.
//   - `manager.rs:93` writes `signature_verified` from the config flag
//     rather than from the actual verification outcome. The audit trail
//     lies about whether anything was checked.
//   - `manager.rs:176-200` (`verify_and_queue`) builds a NOP-sled payload,
//     signs it with `[0u8; 64]`, registers it as `NonosModuleType::System`,
//     and routes it through `crate::modules::register_active_module` into
//     the canonical registry. A zero-signed sled reaches the system
//     registry by design here.
//   - `manager.rs:158`'s `get_timestamp()` reads `_rdtsc()` raw — not
//     monotonic, not auditable.
//
// When the admin syscall moves to the canonical loader with a real trust
// anchor, this whole tree should be deleted. Until then: no new code, no
// new exports, and absolutely no new trust logic in here.

extern crate alloc;

mod api;
mod constants;
mod error;
mod manager;
mod types;

#[cfg(test)]
mod tests;

pub use api::{get_module_info, load_module, start_module, stop_module, unload_module};
pub use manager::NONOS_MODULE_LOADER;
pub use types::{NonosModuleState, NonosModuleType};
