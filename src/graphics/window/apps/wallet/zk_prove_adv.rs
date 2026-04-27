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
use super::types::ADDRESS_LEN;
use super::zk_circuit::*;
use super::zk_helpers::*;
use super::zk_types::*;
use crate::zk_engine::groth16::{FieldElement, Groth16Prover, Groth16Verifier};
use crate::zk_engine::ZKError;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub(crate) fn prove_stealth_spend_key(
    spend_secret: &[u8; 32],
    view_secret: &[u8; 32],
    ephemeral_secret: &[u8; 32],
    stealth_address: &[u8; ADDRESS_LEN],
) -> Result<WalletZKProof, ZKError> {
    if !ZK_INITIALIZED.load(Ordering::SeqCst) {
        super::zk::init_wallet_zk()?;
    }
    let keys = ZK_KEYS.lock();
    let pk = keys.stealth_pk.as_ref().ok_or(ZKError::NotInitialized)?;
    let spend_commitment = compute_spend_pubkey_commitment(spend_secret);
    let witness = vec![
        FieldElement::from_bytes_array(&bytes_to_field_input(stealth_address)),
        FieldElement::from_bytes_array(&spend_commitment),
        FieldElement::from_bytes_array(spend_secret),
        FieldElement::from_bytes_array(view_secret),
        FieldElement::from_bytes_array(ephemeral_secret),
    ];
    let public_inputs = vec![
        FieldElement::from_bytes_array(&bytes_to_field_input(stealth_address)),
        FieldElement::from_bytes_array(&spend_commitment),
    ];
    let circuit = build_stealth_spend_circuit()?;
    let proof = Groth16Prover::prove(pk, &circuit, &witness, &public_inputs, 2)?;
    Ok(WalletZKProof {
        proof_type: WalletProofType::StealthSpendKey,
        proof,
        public_inputs: public_inputs.iter().map(|f| f.to_bytes()).collect(),
        commitment: spend_commitment,
    })
}

pub(crate) fn verify_wallet_proof(proof: &WalletZKProof) -> Result<bool, ZKError> {
    if !ZK_INITIALIZED.load(Ordering::SeqCst) {
        return Err(ZKError::NotInitialized);
    }
    let keys = ZK_KEYS.lock();
    let vk = match proof.proof_type {
        WalletProofType::BalanceOwnership => {
            keys.balance_ownership_vk.as_ref().ok_or(ZKError::NotInitialized)?
        }
        WalletProofType::StealthSpendKey => {
            keys.stealth_vk.as_ref().ok_or(ZKError::NotInitialized)?
        }
    };
    let public_inputs: Vec<FieldElement> =
        proof.public_inputs.iter().map(|bytes| FieldElement::from_bytes_array(bytes)).collect();
    Groth16Verifier::verify(vk, &proof.proof, &public_inputs)
}
