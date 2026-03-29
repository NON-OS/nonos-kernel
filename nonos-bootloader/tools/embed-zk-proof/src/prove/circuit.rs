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

use ark_bls12_381::Fr;
use nonos_attestation_circuit::{
    expected_program_hash_bytes, NonosAttestationCircuit, MIN_HW_LEVEL, PCR_PREIMAGE_LEN,
};

pub struct CircuitParams {
    pub kernel_hash: [u8; 32],
    pub boot_nonce: [u8; 32],
    pub machine_id: [u8; 32],
    pub capsule_commitment: [u8; 32],
    pub program_hash: [u8; 32],
    pub pcr_preimage: [u8; PCR_PREIMAGE_LEN],
    pub hardware_attestation: u64,
}

pub fn create_circuit_params(
    kernel_bytes: &[u8],
    seed: &str,
    boot_nonce: &[u8; 32],
    machine_id: &[u8; 32],
) -> CircuitParams {
    let program_hash = expected_program_hash_bytes();
    let kernel_hash = *blake3::hash(kernel_bytes).as_bytes();

    let mut pcr_preimage = [0u8; PCR_PREIMAGE_LEN];
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed.as_bytes());
    hasher.update(&kernel_hash);
    hasher.update(b"pcr_preimage_v1");
    let hash = hasher.finalize();
    pcr_preimage[..32].copy_from_slice(hash.as_bytes());
    pcr_preimage[32..].copy_from_slice(hash.as_bytes());

    let mut commitment_hasher = blake3::Hasher::new_derive_key("NONOS:CAPSULE:COMMITMENT:v1");
    commitment_hasher.update(&kernel_hash);
    commitment_hasher.update(boot_nonce);
    commitment_hasher.update(machine_id);
    commitment_hasher.update(&program_hash);
    let capsule_commitment = *commitment_hasher.finalize().as_bytes();

    CircuitParams {
        kernel_hash,
        boot_nonce: *boot_nonce,
        machine_id: *machine_id,
        capsule_commitment,
        program_hash,
        pcr_preimage,
        hardware_attestation: MIN_HW_LEVEL + 0x2000,
    }
}

pub fn build_circuit(params: &CircuitParams) -> NonosAttestationCircuit<Fr> {
    NonosAttestationCircuit::new(
        params.kernel_hash,
        params.boot_nonce,
        params.machine_id,
        params.capsule_commitment,
        params.program_hash,
        params.pcr_preimage,
        params.hardware_attestation,
    )
}
