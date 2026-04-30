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

// CANONICAL: vault authority namespace (Phase 1 winner).
// Per CANONICAL_SUBSYSTEM_WINNER_MAP.md and Vault Constitution Law 1
// ("There shall be one canonical vault"), this tree owns secret custody,
// sealing/unsealing, key lifecycle, vault audit, vault diagnostics, and
// vault policy. The frozen `crate::crypto::application::vault` is a
// duplicate authority retained only until its 10 live consumers (crypto
// syscall + 9 shell commands) are retargeted onto this tree (Wave 6 work).
//
// Live external surface today is narrow:
//   - `crate::vault::nonos_vault::initialize_vault()` — boot
//     (`boot/main/graphics_init/components.rs:38`,
//      `userspace/crypto_service/server.rs:31`).
//   - `crate::vault::nonos_vault::NONOS_VAULT` — read-only master-key
//     access (`sys/settings/network/helpers.rs:41`).
// All other `nonos_vault_*` submodules currently have zero external
// consumers; their public surface is retained only because Wave 6
// migration of the frozen-tree shell commands will need it.
//
// REMOVED THIS PASS: `pub mod prelude` block re-exporting every
// `nonos_vault_*` submodule via globs. Zero consumers crate-wide;
// pure surface noise. Authoritative paths are the explicit submodule
// paths (e.g. `crate::vault::nonos_vault::*`), not a prelude.
//
// FOLLOW-UP: the `nonos_*` prefix on this tree's submodules duplicates
// the constitution's product brand into private kernel paths; renaming
// to `{vault, vault_api, vault_audit, vault_crypto, vault_diag,
// vault_policy, vault_seal}` is a later naming-pass cleanup, not Phase 1.

pub mod nonos_vault;
pub mod nonos_vault_api;
pub mod nonos_vault_audit;
pub mod nonos_vault_crypto;
pub mod nonos_vault_diag;
pub mod nonos_vault_policy;
pub mod nonos_vault_seal;

#[cfg(test)]
pub mod tests;
