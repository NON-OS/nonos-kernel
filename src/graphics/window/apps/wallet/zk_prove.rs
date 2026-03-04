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
use core::sync::atomic::Ordering;

use crate::zk_engine::ZKError;
use crate::zk_engine::groth16::{FieldElement, Groth16Prover};

use super::types::ADDRESS_LEN;
use super::zk_types::*;
use super::zk_circuit::*;
use super::zk_helpers::*;

pub(crate) fn prove_balance_ownership(
    balance: u128,
    secret_key: &[u8; 32],
    address: &[u8; ADDRESS_LEN],
) -> Result<WalletZKProof, ZKError> {
    if !ZK_INITIALIZED.load(Ordering::SeqCst) {
        super::zk::init_wallet_zk()?;
    }

    let keys = ZK_KEYS.lock();
    let pk = keys.balance_ownership_pk.as_ref().ok_or(ZKError::NotInitialized)?;

    let blinding = generate_blinding_factor();
    let commitment = compute_balance_commitment(balance, &blinding);

    let witness = vec![
        FieldElement::from_bytes_array(&commitment),
        FieldElement::from_bytes_array(&bytes_to_field_input(address)),
        FieldElement::from_u128(balance),
        FieldElement::from_bytes_array(&blinding),
        FieldElement::from_bytes_array(secret_key),
    ];

    let public_inputs = vec![
        FieldElement::from_bytes_array(&commitment),
        FieldElement::from_bytes_array(&bytes_to_field_input(address)),
    ];

    let circuit = build_balance_ownership_circuit()?;

    let proof = Groth16Prover::prove(pk, &circuit, &witness, &public_inputs, 0)?;

    Ok(WalletZKProof {
        proof_type: WalletProofType::BalanceOwnership,
        proof,
        public_inputs: public_inputs.iter().map(|f| f.to_bytes()).collect(),
        commitment,
    })
}

pub(crate) fn prove_transaction_auth(
    secret_key: &[u8; 32],
    sender: &[u8; ADDRESS_LEN],
    recipient: &[u8; ADDRESS_LEN],
    amount: u128,
) -> Result<WalletZKProof, ZKError> {
    if !ZK_INITIALIZED.load(Ordering::SeqCst) {
        super::zk::init_wallet_zk()?;
    }

    let keys = ZK_KEYS.lock();
    let pk = keys.tx_auth_pk.as_ref().ok_or(ZKError::NotInitialized)?;

    let nonce = generate_blinding_factor();
    let amount_commitment = compute_amount_commitment(amount, &nonce);

    let tx_hash = compute_tx_hash(sender, recipient, &amount_commitment, &nonce);

    let witness = vec![
        FieldElement::from_bytes_array(&tx_hash),
        FieldElement::from_bytes_array(&bytes_to_field_input(sender)),
        FieldElement::from_bytes_array(&bytes_to_field_input(recipient)),
        FieldElement::from_bytes_array(&amount_commitment),
        FieldElement::from_bytes_array(secret_key),
        FieldElement::from_u128(amount),
        FieldElement::from_bytes_array(&nonce),
    ];

    let public_inputs = vec![
        FieldElement::from_bytes_array(&tx_hash),
        FieldElement::from_bytes_array(&bytes_to_field_input(sender)),
        FieldElement::from_bytes_array(&bytes_to_field_input(recipient)),
        FieldElement::from_bytes_array(&amount_commitment),
    ];

    let circuit = build_transaction_auth_circuit()?;

    let proof = Groth16Prover::prove(pk, &circuit, &witness, &public_inputs, 1)?;

    Ok(WalletZKProof {
        proof_type: WalletProofType::TransactionAuth,
        proof,
        public_inputs: public_inputs.iter().map(|f| f.to_bytes()).collect(),
        commitment: amount_commitment,
    })
}

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

pub(crate) fn prove_balance_sufficiency(
    actual_balance: u128,
    minimum_required: u128,
) -> Result<WalletZKProof, ZKError> {
    if actual_balance < minimum_required {
        return Err(ZKError::InvalidInput);
    }

    if !ZK_INITIALIZED.load(Ordering::SeqCst) {
        super::zk::init_wallet_zk()?;
    }

    let keys = ZK_KEYS.lock();
    let pk = keys.sufficiency_pk.as_ref().ok_or(ZKError::NotInitialized)?;

    let blinding = generate_blinding_factor();
    let balance_commitment = compute_balance_commitment(actual_balance, &blinding);

    let difference = actual_balance - minimum_required;

    let witness = vec![
        FieldElement::from_u128(minimum_required),
        FieldElement::from_bytes_array(&balance_commitment),
        FieldElement::from_u128(actual_balance),
        FieldElement::from_bytes_array(&blinding),
        FieldElement::from_u128(difference),
    ];

    let public_inputs = vec![
        FieldElement::from_u128(minimum_required),
        FieldElement::from_bytes_array(&balance_commitment),
    ];

    let circuit = build_balance_sufficiency_circuit()?;

    let proof = Groth16Prover::prove(pk, &circuit, &witness, &public_inputs, 3)?;

    Ok(WalletZKProof {
        proof_type: WalletProofType::BalanceSufficiency,
        proof,
        public_inputs: public_inputs.iter().map(|f| f.to_bytes()).collect(),
        commitment: balance_commitment,
    })
}

pub(crate) fn verify_wallet_proof(proof: &WalletZKProof) -> Result<bool, ZKError> {
    use crate::zk_engine::groth16::Groth16Verifier;

    if !ZK_INITIALIZED.load(Ordering::SeqCst) {
        return Err(ZKError::NotInitialized);
    }

    let keys = ZK_KEYS.lock();

    let vk = match proof.proof_type {
        WalletProofType::BalanceOwnership => {
            keys.balance_ownership_vk.as_ref().ok_or(ZKError::NotInitialized)?
        }
        WalletProofType::TransactionAuth => {
            keys.tx_auth_vk.as_ref().ok_or(ZKError::NotInitialized)?
        }
        WalletProofType::StealthSpendKey => {
            keys.stealth_vk.as_ref().ok_or(ZKError::NotInitialized)?
        }
        WalletProofType::BalanceSufficiency => {
            keys.sufficiency_vk.as_ref().ok_or(ZKError::NotInitialized)?
        }
    };

    let public_inputs: Vec<FieldElement> = proof.public_inputs
        .iter()
        .map(|bytes| FieldElement::from_bytes_array(bytes))
        .collect();

    Groth16Verifier::verify(vk, &proof.proof, &public_inputs)
}
