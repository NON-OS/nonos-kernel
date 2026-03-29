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
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::constants::{
    expected_program_hash_bytes, BuildProvenance, MIN_HW_LEVEL, MIN_PCR_ENTROPY_BYTES,
    PCR_PREIMAGE_LEN,
};

#[derive(Clone)]
pub struct NonosAttestationCircuit<F: PrimeField> {
    pub kernel_hash: Option<[u8; 32]>,
    pub boot_nonce: Option<[u8; 32]>,
    pub machine_id: Option<[u8; 32]>,
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
        let mut dummy_pcr = [0u8; PCR_PREIMAGE_LEN];
        for (i, byte) in dummy_pcr.iter_mut().take(MIN_PCR_ENTROPY_BYTES).enumerate() {
            *byte = (i as u8).wrapping_add(1);
        }

        let mut dummy_commitment = [0u8; 32];
        dummy_commitment[0] = 1;

        let mut dummy_kernel_hash = [0u8; 32];
        dummy_kernel_hash[0] = 0xDE;
        dummy_kernel_hash[1] = 0xAD;

        let mut dummy_nonce = [0u8; 32];
        dummy_nonce[0] = 0xCA;
        dummy_nonce[1] = 0xFE;

        let mut dummy_machine_id = [0u8; 32];
        dummy_machine_id[0] = 0xBE;
        dummy_machine_id[1] = 0xEF;

        Self {
            kernel_hash: Some(dummy_kernel_hash),
            boot_nonce: Some(dummy_nonce),
            machine_id: Some(dummy_machine_id),
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
        kernel_hash: [u8; 32],
        boot_nonce: [u8; 32],
        machine_id: [u8; 32],
        capsule_commitment: [u8; 32],
        program_hash: [u8; 32],
        pcr_preimage: [u8; PCR_PREIMAGE_LEN],
        hardware_attestation: u64,
    ) -> Self {
        Self {
            kernel_hash: Some(kernel_hash),
            boot_nonce: Some(boot_nonce),
            machine_id: Some(machine_id),
            capsule_commitment: Some(capsule_commitment),
            program_hash: Some(program_hash),
            pcr_preimage: Some(pcr_preimage),
            hardware_attestation: Some(hardware_attestation),
            build_provenance: None,
            expected_provenance_hash: None,
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for NonosAttestationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let kernel_hash = self.kernel_hash.ok_or(SynthesisError::AssignmentMissing)?;
        let boot_nonce = self.boot_nonce.ok_or(SynthesisError::AssignmentMissing)?;
        let machine_id = self.machine_id.ok_or(SynthesisError::AssignmentMissing)?;
        let capsule_bytes = self.capsule_commitment.ok_or(SynthesisError::AssignmentMissing)?;
        let program_hash = self.program_hash.ok_or(SynthesisError::AssignmentMissing)?;
        let pcr_bytes = self.pcr_preimage.ok_or(SynthesisError::AssignmentMissing)?;
        let hw_level = self.hardware_attestation.ok_or(SynthesisError::AssignmentMissing)?;

        let kernel_var = UInt8::<F>::new_input_vec(cs.clone(), &kernel_hash)?;
        let nonce_var = UInt8::<F>::new_input_vec(cs.clone(), &boot_nonce)?;
        let machine_var = UInt8::<F>::new_input_vec(cs.clone(), &machine_id)?;
        let capsule_var = UInt8::<F>::new_input_vec(cs.clone(), &capsule_bytes)?;
        let program_var = UInt8::<F>::new_input_vec(cs.clone(), &program_hash)?;
        let pcr_var = UInt8::<F>::new_witness_vec(cs.clone(), &pcr_bytes)?;
        let hw_var = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(hw_level)))?;

        enforce_hash_nonzero(cs.clone(), &kernel_var)?;
        enforce_hash_nonzero(cs.clone(), &nonce_var)?;
        enforce_hash_nonzero(cs.clone(), &machine_var)?;
        enforce_hash_nonzero(cs.clone(), &capsule_var)?;

        let expected_hash = expected_program_hash_bytes();
        for (i, &expected_byte) in expected_hash.iter().enumerate() {
            let expected_var = UInt8::<F>::new_constant(cs.clone(), expected_byte)?;
            program_var[i].enforce_equal(&expected_var)?;
        }

        enforce_pcr_entropy(cs.clone(), &pcr_var)?;

        let min_hw = FpVar::<F>::new_constant(cs.clone(), F::from(MIN_HW_LEVEL))?;
        let hw_diff = &hw_var - &min_hw;
        hw_diff.enforce_not_equal(&FpVar::zero())?;

        Ok(())
    }
}

fn enforce_hash_nonzero<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    bytes: &[UInt8<F>],
) -> Result<(), SynthesisError> {
    let mut sum = FpVar::<F>::zero();
    let one = FpVar::<F>::one();
    let fp_zero = FpVar::<F>::zero();
    for byte in bytes {
        let zero = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
        let is_nonzero = byte.is_neq(&zero)?;
        sum += is_nonzero.select(&one, &fp_zero)?;
    }
    sum.enforce_not_equal(&FpVar::zero())?;
    Ok(())
}

fn enforce_pcr_entropy<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    pcr: &[UInt8<F>],
) -> Result<(), SynthesisError> {
    let mut count = FpVar::<F>::zero();
    let one = FpVar::<F>::one();
    let fp_zero = FpVar::<F>::zero();
    for byte in pcr {
        let zero = UInt8::<F>::new_constant(cs.clone(), 0u8)?;
        let is_nonzero = byte.is_neq(&zero)?;
        count += is_nonzero.select(&one, &fp_zero)?;
    }
    let min = FpVar::<F>::new_constant(cs.clone(), F::from(MIN_PCR_ENTROPY_BYTES as u64))?;
    let diff = &count - &min;
    diff.enforce_not_equal(&FpVar::zero())?;
    Ok(())
}
