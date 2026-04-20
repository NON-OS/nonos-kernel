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
use crate::crypto::ed25519::{KeyPair, Signature, verify};
use super::EncryptionError;

pub struct IpcVerifier {
    public_key: [u8; 32],
    expected_identity: [u8; 32],
}

impl IpcVerifier {
    pub fn new(sender_identity: &str) -> Result<Self, EncryptionError> {
        let identity_hash = super::derive_identity_key::derive_identity_key(sender_identity)?;
        let keypair = KeyPair::from_seed(identity_hash);

        Ok(Self {
            public_key: keypair.public,
            expected_identity: identity_hash,
        })
    }

    pub fn verify_message(&self, data: &[u8], metadata: &[u8], signature_bytes: &[u8; 64]) -> Result<bool, EncryptionError> {
        let mut message = Vec::with_capacity(data.len() + metadata.len() + 32);
        message.extend_from_slice(&self.expected_identity);
        message.extend_from_slice(data);
        message.extend_from_slice(metadata);

        let signature = Signature::from_bytes(signature_bytes);
        let valid = verify(&self.public_key, &message, &signature);
        Ok(valid)
    }

    pub fn expected_identity(&self) -> &[u8; 32] {
        &self.expected_identity
    }
}