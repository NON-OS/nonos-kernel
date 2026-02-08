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

use core::marker::PhantomData;

use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
};

use crate::constants::{
    expected_program_hash_bytes, BuildProvenance, MIN_HW_LEVEL, MIN_PCR_ENTROPY_BYTES,
    PCR_PREIMAGE_LEN,
};

#[derive(Clone)]
pub struct NonosAttestationCircuit<F: PrimeField> {
    pub capsule_commitment: Option<[u8; 32]>,
    pub program_hash: Option<[u8; 32]>,
    pub pcr_preimage: Option<[u8; PCR_PREIMAGE_LEN]>,
    pub hardware_attestation: Option<u64>,
    pub build_provenance: Option<BuildProvenance>,
    pub expected_provenance_hash: Option<[u8; 32]>,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> Default for NonosAttestationCircuit<F> {
    fn default() -> Self {
        // Provide dummy values for circuit setup (key generation)
        // These values satisfy the circuit constraints for setup purposes
        let mut dummy_pcr = [0u8; PCR_PREIMAGE_LEN];
        // Fill with non-zero bytes to satisfy MIN_PCR_ENTROPY_BYTES constraint
        for i in 0..MIN_PCR_ENTROPY_BYTES {
            dummy_pcr[i] = (i as u8).wrapping_add(1);
        }

        // Dummy capsule commitment (non-zero)
        let mut dummy_commitment = [0u8; 32];
        dummy_commitment[0] = 1;

        Self {
            capsule_commitment: Some(dummy_commitment),
            program_hash: Some(expected_program_hash_bytes()),
            pcr_preimage: Some(dummy_pcr),
            hardware_attestation: Some(MIN_HW_LEVEL + 1),
            build_provenance: None,
            expected_provenance_hash: None,
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> NonosAttestationCircuit<F> {
    pub fn new(
        capsule_commitment: [u8; 32],
        program_hash: [u8; 32],
        pcr_preimage: [u8; PCR_PREIMAGE_LEN],
        hardware_attestation: u64,
    ) -> Self {
        Self {
            capsule_commitment: Some(capsule_commitment),
            program_hash: Some(program_hash),
            pcr_preimage: Some(pcr_preimage),
            hardware_attestation: Some(hardware_attestation),
            build_provenance: None,
            expected_provenance_hash: None,
            _phantom: PhantomData,
        }
    }

    pub fn with_build_provenance(
        capsule_commitment: [u8; 32],
        program_hash: [u8; 32],
        pcr_preimage: [u8; PCR_PREIMAGE_LEN],
        hardware_attestation: u64,
        build_provenance: BuildProvenance,
        expected_provenance_hash: [u8; 32],
    ) -> Self {
        Self {
            capsule_commitment: Some(capsule_commitment),
            program_hash: Some(program_hash),
            pcr_preimage: Some(pcr_preimage),
            hardware_attestation: Some(hardware_attestation),
            build_provenance: Some(build_provenance),
            expected_provenance_hash: Some(expected_provenance_hash),
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for NonosAttestationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let capsule_commitment_bytes = self
            .capsule_commitment
            .ok_or(SynthesisError::AssignmentMissing)?;
        let program_hash_bytes = self
            .program_hash
            .ok_or(SynthesisError::AssignmentMissing)?;
        let pcr_bytes = self
            .pcr_preimage
            .ok_or(SynthesisError::AssignmentMissing)?;
        let hw_level = self
            .hardware_attestation
            .ok_or(SynthesisError::AssignmentMissing)?;

        let capsule_var = UInt8::<F>::new_input_vec(cs.clone(), &capsule_commitment_bytes)?;
        let program_hash_var = UInt8::<F>::new_input_vec(cs.clone(), &program_hash_bytes)?;

        let pcr_var = UInt8::<F>::new_witness_vec(cs.clone(), &pcr_bytes)?;
        let hw_var = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(hw_level)))?;

        let expected_hash = expected_program_hash_bytes();
        for (i, &expected_byte) in expected_hash.iter().enumerate() {
            let expected_var = UInt8::<F>::new_constant(cs.clone(), expected_byte)?;
            program_hash_var[i].enforce_equal(&expected_var)?;
        }

        let mut pcr_nonzero_count = FpVar::<F>::zero();
        let one = FpVar::<F>::one();
        let fp_zero = FpVar::<F>::zero();
        for byte in &pcr_var {
            let zero_byte = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
            let is_nonzero = byte.is_neq(&zero_byte)?;
            pcr_nonzero_count = pcr_nonzero_count + is_nonzero.select(&one, &fp_zero)?;
        }
        let min_entropy =
            FpVar::<F>::new_constant(cs.clone(), F::from(MIN_PCR_ENTROPY_BYTES as u64))?;
        let pcr_minus_min = &pcr_nonzero_count - &min_entropy;
        pcr_minus_min.enforce_not_equal(&FpVar::zero())?;

        let min_hw_var = FpVar::<F>::new_constant(cs.clone(), F::from(MIN_HW_LEVEL))?;
        let hw_minus_min = &hw_var - &min_hw_var;
        hw_minus_min.enforce_not_equal(&FpVar::zero())?;

        let mut cc_nonzero = Boolean::FALSE;
        for byte in &capsule_var {
            let zero_byte = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
            let is_nonzero = byte.is_neq(&zero_byte)?;
            cc_nonzero = cc_nonzero.or(&is_nonzero)?;
        }
        cc_nonzero.enforce_equal(&Boolean::TRUE)?;

        if let (Some(provenance), Some(expected_hash)) =
            (self.build_provenance, self.expected_provenance_hash)
        {
            let computed_hash = provenance.compute_composite_hash();

            let provenance_var =
                UInt8::<F>::new_witness_vec(cs.clone(), &provenance.to_bytes())?;
            let computed_hash_var = UInt8::<F>::new_input_vec(cs.clone(), &computed_hash)?;
            let expected_hash_var = UInt8::<F>::new_input_vec(cs.clone(), &expected_hash)?;

            for (i, expected_byte) in expected_hash_var.iter().enumerate() {
                computed_hash_var[i].enforce_equal(expected_byte)?;
            }

            let mut source_tree_nonzero = Boolean::FALSE;
            for byte in &provenance_var[0..32] {
                let zero_byte = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
                let is_nonzero = byte.is_neq(&zero_byte)?;
                source_tree_nonzero = source_tree_nonzero.or(&is_nonzero)?;
            }
            source_tree_nonzero.enforce_equal(&Boolean::TRUE)?;

            let mut cargo_lock_nonzero = Boolean::FALSE;
            for byte in &provenance_var[32..64] {
                let zero_byte = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
                let is_nonzero = byte.is_neq(&zero_byte)?;
                cargo_lock_nonzero = cargo_lock_nonzero.or(&is_nonzero)?;
            }
            cargo_lock_nonzero.enforce_equal(&Boolean::TRUE)?;

            let mut rustc_version_nonzero = Boolean::FALSE;
            for byte in &provenance_var[64..96] {
                let zero_byte = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
                let is_nonzero = byte.is_neq(&zero_byte)?;
                rustc_version_nonzero = rustc_version_nonzero.or(&is_nonzero)?;
            }
            rustc_version_nonzero.enforce_equal(&Boolean::TRUE)?;

            let mut build_config_nonzero = Boolean::FALSE;
            for byte in &provenance_var[96..128] {
                let zero_byte = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
                let is_nonzero = byte.is_neq(&zero_byte)?;
                build_config_nonzero = build_config_nonzero.or(&is_nonzero)?;
            }
            build_config_nonzero.enforce_equal(&Boolean::TRUE)?;
        }

        Ok(())
    }
}
