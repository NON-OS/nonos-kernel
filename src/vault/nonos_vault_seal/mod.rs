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

mod erase;
mod seal;
mod store;
mod types;
mod unseal;

pub use store::{VaultSealStore, VAULT_SEAL_STORE};
pub use types::{SealPolicy, SealedSecret};

pub fn seal_secret(
    plaintext: &[u8],
    aad: &[u8],
    policy: SealPolicy,
) -> Result<SealedSecret, &'static str> {
    VAULT_SEAL_STORE.seal_secret(plaintext, aad, policy)
}

pub fn unseal_secret(sealed: &SealedSecret) -> Result<alloc::vec::Vec<u8>, &'static str> {
    VAULT_SEAL_STORE.unseal_secret(sealed)
}

pub fn list_sealed() -> alloc::vec::Vec<SealedSecret> {
    VAULT_SEAL_STORE.list_sealed()
}

pub fn secure_erase_sealed(backend: Option<SealPolicy>) {
    VAULT_SEAL_STORE.secure_erase_sealed(backend)
}
