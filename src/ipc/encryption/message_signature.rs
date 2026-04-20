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
use crate::crypto::asymmetric::curve25519::PublicKey;
use super::EncryptionError;

#[derive(Debug, Clone)]
pub struct MessageSignature {
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
    pub timestamp: u64,
}

impl MessageSignature {
    pub fn new(signature: [u8; 64], public_key: PublicKey, timestamp: u64) -> Self {
        Self {
            signature,
            public_key: public_key,
            timestamp,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + 32 + 8);
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncryptionError> {
        if data.len() != 104 {
            return Err(EncryptionError::AuthenticationFailed);
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[0..64]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[64..96]);

        let timestamp = u64::from_le_bytes([
            data[96], data[97], data[98], data[99],
            data[100], data[101], data[102], data[103],
        ]);

        Ok(Self {
            signature,
            public_key,
            timestamp,
        })
    }
}