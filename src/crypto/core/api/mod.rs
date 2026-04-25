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

mod entropy;
mod hkdf;
mod init;
mod keygen;
mod memory;
mod plonk;
mod random;
mod types;
mod verify;

pub use entropy::estimate_entropy;
pub use hkdf::hkdf_expand_labeled;
pub use init::{feature_summary, init, init_crypto_subsystem};
pub use keygen::{generate_keypair, sig};
pub use memory::{hash_memory_region, secure_erase_memory_region, secure_zero};
pub use plonk::{generate_plonk_proof, verify_plonk_proof};
pub use random::{
    fill_random, generate_secure_key, generate_secure_key_checked, secure_random_u32,
    secure_random_u64, secure_random_u8,
};
pub use types::SignatureAlgorithm;
pub use verify::{ed25519_verify, verify_signature};
