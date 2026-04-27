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
use crate::zk_engine::groth16::{FieldElement, Groth16Prover};
use crate::zk_engine::ZKError;
use alloc::vec;
use core::sync::atomic::Ordering;

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

pub(crate) use super::zk_prove_adv::{prove_stealth_spend_key, verify_wallet_proof};
