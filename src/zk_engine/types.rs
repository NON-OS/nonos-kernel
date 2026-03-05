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

use alloc::{vec::Vec, string::String};
use core::sync::atomic::{AtomicU32, AtomicU64};
use super::groth16::Proof;

#[derive(Debug, Clone)]
pub struct ZKConfig {
    pub max_constraints: usize,
    pub max_witnesses: usize,
    pub enable_preprocessing: bool,
    pub enable_verification_cache: bool,
    pub trusted_setup_path: Option<String>,
}

impl Default for ZKConfig {
    fn default() -> Self {
        Self {
            max_constraints: 1_000_000,
            max_witnesses: 100_000,
            enable_preprocessing: true,
            enable_verification_cache: true,
            trusted_setup_path: None,
        }
    }
}

#[derive(Debug)]
pub struct ZKStats {
    pub proofs_generated: AtomicU64,
    pub proofs_verified: AtomicU64,
    pub verification_failures: AtomicU64,
    pub circuits_compiled: AtomicU32,
    pub total_proving_time_ms: AtomicU64,
    pub total_verification_time_ms: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ZKProof {
    pub circuit_id: u32,
    pub proof_data: Proof,
    pub public_inputs: Vec<Vec<u8>>,
    pub proof_hash: [u8; 32],
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub enum ZKError {
    InvalidCircuit,
    InvalidWitness,
    ProvingFailed,
    VerificationFailed,
    CircuitNotFound,
    InvalidProof,
    SetupError,
    OutOfMemory,
    InvalidParameters,
    TrustedSetupNotFound,
    InvalidFormat,
    CryptoError,
    InvalidInput,
    NetworkError,
    AttestationError(String),
    NotInitialized,
}
