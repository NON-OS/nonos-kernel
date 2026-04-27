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

mod key_vault;
mod memory;
mod random;
mod string_vault;
mod types;
mod zeroize;

pub use key_vault::{
    delete_vault_key, generate_and_store_ed25519_keypair, get_public_key, get_signing_key,
    list_vault_keys, store_keypair,
};
pub use memory::{allocate_secure_memory, deallocate_secure_memory};
pub use random::{generate_random_bytes, random_u64};
pub use string_vault::{delete_key, init_vault, list_keys, retrieve_key, store_key};
pub use types::{KeyEntry, VaultKeyAlgorithm, VaultPublicKey};
pub use zeroize::zeroize_all_keys;
