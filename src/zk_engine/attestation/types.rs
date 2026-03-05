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

//! Attestation type definitions.

use alloc::{vec::Vec, string::String};
use crate::zk_engine::groth16::{FieldElement, Proof};
use crate::zk_engine::ZKError;
use crate::crypto::{hash::blake3_hash, ed25519::Signature as Ed25519Signature};
use crate::memory::VirtAddr;

/// Complete kernel attestation
#[derive(Debug, Clone)]
pub struct KernelAttestation {
    pub measurement: KernelMeasurement,
    pub signature: Ed25519Signature,
    pub zk_proof: Option<Proof>,
    pub public_key: [u8; 32],
    pub timestamp: u64,
}

impl KernelAttestation {
    /// Serialize attestation for transmission
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Measurement
        data.extend_from_slice(&self.measurement.to_bytes());

        // Signature
        data.extend_from_slice(&self.signature.to_bytes());

        // Public key
        data.extend_from_slice(&self.public_key);

        // Timestamp
        data.extend_from_slice(&self.timestamp.to_le_bytes());

        // ZK proof (if present)
        if let Some(ref proof) = self.zk_proof {
            data.push(1); // Has proof marker
            data.extend_from_slice(&proof.serialize());
        } else {
            data.push(0); // No proof marker
        }

        data
    }

    /// Deserialize attestation
    pub fn deserialize(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 128 { // Minimum size check
            return Err(ZKError::InvalidFormat);
        }

        let mut offset = 0;

        // Parse measurement (simplified)
        let measurement = KernelMeasurement::from_bytes(&data[offset..offset + 96])?;
        offset += 96;

        // Parse Ed25519 signature
        let signature = {
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&data[offset..offset + 64]);
            Ed25519Signature::from_bytes(&sig_bytes)
        };
        if data[offset..offset + 64].len() != 64 {
            return Err(ZKError::InvalidFormat);
        }
        offset += 64;

        // Parse public key
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Parse timestamp
        let timestamp = u64::from_le_bytes(
            data[offset..offset + 8].try_into().map_err(|_| ZKError::InvalidFormat)?
        );
        offset += 8;

        // Parse ZK proof
        let zk_proof = if data[offset] == 1 {
            offset += 1;
            Some(Proof::deserialize(&data[offset..])?)
        } else {
            None
        };

        Ok(Self {
            measurement,
            signature,
            zk_proof,
            public_key,
            timestamp,
        })
    }
}

/// Kernel measurement data
#[derive(Debug, Clone)]
pub struct KernelMeasurement {
    pub code_hash: [u8; 32],
    pub data_hash: [u8; 32],
    pub config_hash: [u8; 32],
    pub memory_layout: MemoryLayout,
    pub module_hashes: Vec<ModuleHash>,
    pub integrity_hash: [u8; 32],
}

impl KernelMeasurement {
    pub fn new() -> Self {
        Self {
            code_hash: [0; 32],
            data_hash: [0; 32],
            config_hash: [0; 32],
            memory_layout: MemoryLayout::default(),
            module_hashes: Vec::new(),
            integrity_hash: [0; 32],
        }
    }

    pub fn compute_integrity_hash(&self) -> [u8; 32] {
        let mut hasher_input = Vec::new();

        hasher_input.extend_from_slice(&self.code_hash);
        hasher_input.extend_from_slice(&self.data_hash);
        hasher_input.extend_from_slice(&self.config_hash);
        hasher_input.extend_from_slice(&self.memory_layout.to_bytes());

        for module in &self.module_hashes {
            hasher_input.extend_from_slice(&module.hash);
        }

        blake3_hash(&hasher_input)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&self.code_hash);
        data.extend_from_slice(&self.data_hash);
        data.extend_from_slice(&self.config_hash);
        data.extend_from_slice(&self.memory_layout.to_bytes());
        data.extend_from_slice(&self.integrity_hash);

        // Module count and hashes
        data.extend_from_slice(&(self.module_hashes.len() as u32).to_le_bytes());
        for module in &self.module_hashes {
            data.extend_from_slice(module.name.as_bytes());
            data.extend_from_slice(&[0]); // Null terminator
            data.extend_from_slice(&module.hash);
            data.extend_from_slice(&module.address.as_u64().to_le_bytes());
            data.extend_from_slice(&module.size.to_le_bytes());
        }

        data
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 96 {
            return Err(ZKError::InvalidFormat);
        }

        let mut measurement = Self::new();
        let mut offset = 0;

        measurement.code_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        measurement.data_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        measurement.config_hash.copy_from_slice(&data[offset..offset + 32]);

        // Parse memory layout and integrity hash (simplified)
        // In practice, would need proper parsing

        Ok(measurement)
    }

    pub fn to_field_elements(&self) -> Result<Vec<FieldElement>, ZKError> {
        let mut elements = Vec::new();

        // Convert hashes to field elements
        elements.push(FieldElement::from_bytes(&self.code_hash)?);
        elements.push(FieldElement::from_bytes(&self.data_hash)?);
        elements.push(FieldElement::from_bytes(&self.config_hash)?);
        elements.push(FieldElement::from_bytes(&self.integrity_hash)?);

        Ok(elements)
    }

    pub fn to_witness(&self) -> Result<Vec<Vec<u8>>, ZKError> {
        let mut witness = Vec::new();

        witness.push(self.code_hash.to_vec());
        witness.push(self.data_hash.to_vec());
        witness.push(self.config_hash.to_vec());
        witness.push(self.integrity_hash.to_vec());

        Ok(witness)
    }
}

/// Memory layout information
#[derive(Debug, Clone)]
pub struct MemoryLayout {
    pub kernel_start: VirtAddr,
    pub kernel_end: VirtAddr,
    pub user_start: VirtAddr,
    pub user_end: VirtAddr,
    pub heap_start: VirtAddr,
    pub heap_end: VirtAddr,
}

impl Default for MemoryLayout {
    fn default() -> Self {
        Self {
            kernel_start: VirtAddr::new(0),
            kernel_end: VirtAddr::new(0),
            user_start: VirtAddr::new(0),
            user_end: VirtAddr::new(0),
            heap_start: VirtAddr::new(0),
            heap_end: VirtAddr::new(0),
        }
    }
}

impl MemoryLayout {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&self.kernel_start.as_u64().to_le_bytes());
        data.extend_from_slice(&self.kernel_end.as_u64().to_le_bytes());
        data.extend_from_slice(&self.user_start.as_u64().to_le_bytes());
        data.extend_from_slice(&self.user_end.as_u64().to_le_bytes());
        data.extend_from_slice(&self.heap_start.as_u64().to_le_bytes());
        data.extend_from_slice(&self.heap_end.as_u64().to_le_bytes());

        data
    }
}

/// Module hash information
#[derive(Debug, Clone)]
pub struct ModuleHash {
    pub name: String,
    pub hash: [u8; 32],
    pub address: VirtAddr,
    pub size: usize,
}
