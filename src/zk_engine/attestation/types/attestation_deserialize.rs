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

use super::attestation::KernelAttestation;
use super::measurement::KernelMeasurement;
use crate::crypto::ed25519::Signature as Ed25519Signature;
use crate::zk_engine::groth16::Proof;
use crate::zk_engine::ZKError;

impl KernelAttestation {
    pub fn deserialize(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 128 {
            return Err(ZKError::InvalidFormat);
        }

        let mut offset = 0;

        let measurement = KernelMeasurement::from_bytes(&data[offset..offset + 96])?;
        offset += 96;

        let signature = {
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&data[offset..offset + 64]);
            Ed25519Signature::from_bytes(&sig_bytes)
        };
        offset += 64;

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let timestamp = u64::from_le_bytes(
            data[offset..offset + 8].try_into().map_err(|_| ZKError::InvalidFormat)?,
        );
        offset += 8;

        let zk_proof = if data[offset] == 1 {
            offset += 1;
            Some(Proof::deserialize(&data[offset..])?)
        } else {
            None
        };

        Ok(Self { measurement, signature, zk_proof, public_key, timestamp })
    }
}
