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

mod types;
mod string_vault;
mod random;
mod memory;
mod key_vault;
mod zeroize;

pub use types::{VaultPublicKey, VaultKeyAlgorithm, KeyEntry};
pub use string_vault::{init_vault, store_key, retrieve_key, delete_key, list_keys};
pub use random::{generate_random_bytes, random_u64};
pub use memory::{allocate_secure_memory, deallocate_secure_memory};
pub use key_vault::{get_signing_key, get_public_key, store_keypair, generate_and_store_ed25519_keypair, delete_vault_key, list_vault_keys};
pub use zeroize::zeroize_all_keys;
