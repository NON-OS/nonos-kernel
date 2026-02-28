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

extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, Clone, Default)]
pub struct VaultPublicKey {
    pub key_data: Vec<u8>,
    pub algorithm: VaultKeyAlgorithm,
}

#[derive(Debug, Clone, Default)]
pub enum VaultKeyAlgorithm {
    #[default]
    Ed25519,
    Rsa2048,
    Secp256k1,
}

impl VaultPublicKey {
    pub fn new(key_data: Vec<u8>, algorithm: VaultKeyAlgorithm) -> Self {
        Self { key_data, algorithm }
    }

    pub fn from_ed25519(public_key: &[u8]) -> Self {
        Self {
            key_data: public_key.to_vec(),
            algorithm: VaultKeyAlgorithm::Ed25519,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: VaultKeyAlgorithm,
    pub created_ms: u64,
}
