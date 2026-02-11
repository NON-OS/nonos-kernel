// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

// ZK submodules
pub mod attest;
pub mod binding;
pub mod errors;
pub mod registry;
pub mod section;
pub mod transcript;
pub mod verify;

// Re-export
pub use errors::ZkError;

// Re-export 
pub use binding::{
    compute_capsule_commitment, compute_commit, is_manifest_binding_enabled, select_binding,
    verify_commitment, BindingInput, DS_COMMITMENT, MAX_MANIFEST_SIZE,
};

// Re-export 
pub use verify::{ct_eq32, derive_program_hash, verify_proof, ZkProof, ZkVerifyResult};
#[cfg(feature = "zk-groth16")]
pub use verify::{groth16_verify, GrothErr, GROTH16_PROOF_LEN};
pub use verify::{DS_PROGRAM_HASH, MAX_INPUT_SIZE, MAX_PROOF_SIZE};

// Re-export 
pub use attest::{
    calculate_proof_block_size, create_zk_proof_block, find_zk_proof_offset, has_zk_proof,
    parse_zk_proof, parse_zk_proof_header, verify_boot_attestation,
    verify_boot_attestation_with_manifest, BootAttestationResult, ZkProofBlock, GROTH16_PROOF_SIZE,
    ZK_PROOF_HEADER_SIZE, ZK_PROOF_MAGIC, ZK_PROOF_VERSION,
};

pub use transcript::{Transcript, TRANSCRIPT_DOMAIN_BOOT, TRANSCRIPT_DOMAIN_CIRCUIT};

// Re-export 
pub use section::{parse_section, validate_section};

// Re-export
pub use registry::{derive_circuit_key, verify_circuit_key_derivation};
pub use registry::{
    parse_circuit_section, CircuitCategory, CircuitEntry, CircuitPermission, CircuitSectionEntry,
    CircuitSectionHeader, DynamicCircuitEntry, DynamicCircuitStore, CIRCUIT_SECTION_MAGIC,
};

#[cfg(feature = "zk-groth16")]
pub use registry::{
    circuits_with_permission, has_permission, lookup, lookup_circuit, CORE_CIRCUITS, ENTRIES,
    PROGRAM_HASH_BOOT_AUTHORITY, PROGRAM_HASH_RECOVERY_KEY, PROGRAM_HASH_UPDATE_AUTHORITY,
    VK_BOOT_AUTHORITY_BLS12_381_GROTH16, VK_RECOVERY_KEY_BLS12_381_GROTH16,
    VK_UPDATE_AUTHORITY_BLS12_381_GROTH16,
};
