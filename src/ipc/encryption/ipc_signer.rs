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
use super::EncryptionError;
use crate::crypto::ed25519::{sign, KeyPair};
use alloc::vec::Vec;

pub struct IpcSigner {
    keypair: KeyPair,
    identity: [u8; 32],
}

impl IpcSigner {
    pub fn new(identity: &str) -> Result<Self, EncryptionError> {
        let identity_hash = super::derive_identity_key::derive_identity_key(identity)?;
        let keypair = KeyPair::from_seed(identity_hash);

        Ok(Self { keypair, identity: identity_hash })
    }

    pub fn sign_message(&self, data: &[u8], metadata: &[u8]) -> Result<[u8; 64], EncryptionError> {
        let mut message = Vec::with_capacity(data.len() + metadata.len() + 32);
        message.extend_from_slice(&self.identity);
        message.extend_from_slice(data);
        message.extend_from_slice(metadata);

        let signature = sign(&self.keypair, &message);
        Ok(signature.to_bytes())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public
    }

    pub fn identity(&self) -> &[u8; 32] {
        &self.identity
    }
}
