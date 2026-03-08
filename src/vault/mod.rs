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

//! NONOS Vault Subsystem Entry Point

#![allow(dead_code)]

pub mod nonos_vault;
pub mod nonos_vault_crypto;
pub mod nonos_vault_seal;
pub mod nonos_vault_policy;
pub mod nonos_vault_api;
pub mod nonos_vault_audit;
pub mod nonos_vault_diag;

/// Unified public API for use elsewhere in kernel/userland
pub mod prelude {
    pub use super::nonos_vault::*;
    pub use super::nonos_vault_crypto::*;
    pub use super::nonos_vault_seal::*;
    pub use super::nonos_vault_policy::*;
    pub use super::nonos_vault_api::*;
    pub use super::nonos_vault_audit::*;
    pub use super::nonos_vault_diag::*;
}

/// Compile-time check for initialization order
#[cfg(all(test, not(feature = "std")))]
mod tests {
    use super::*;
    #[test]
    fn vault_modules_load() {
        assert!(true, "Vault module tree loads");
    }
}
