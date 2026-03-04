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

use crate::zk_engine::ZKError;
use crate::zk_engine::circuit::{Circuit, CircuitBuilder, LinearCombination};
use crate::zk_engine::groth16::FieldElement;

pub(super) fn build_balance_ownership_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let commitment_hash = builder.alloc_input(Some("commitment_hash"));
    let address = builder.alloc_input(Some("address"));

    let balance = builder.alloc_variable(Some("balance"));
    let blinding_factor = builder.alloc_variable(Some("blinding_factor"));
    let secret_key = builder.alloc_variable(Some("secret_key"));

    let balance_lc = LinearCombination::from_variable(balance);
    let blinding_lc = LinearCombination::from_variable(blinding_factor);

    let commitment_lc = LinearCombination::from_variable(commitment_hash);
    let hash_intermediate = builder.alloc_variable(Some("hash_intermediate"));

    builder.enforce_multiplication(balance, blinding_factor, hash_intermediate);

    let mut combined_lc = balance_lc;
    combined_lc.add_term(blinding_factor, FieldElement::one());
    builder.enforce_equal(commitment_lc, combined_lc.clone());
    let _ = blinding_lc;

    let derived_address = builder.alloc_variable(Some("derived_address"));

    builder.enforce_multiplication(secret_key, secret_key, derived_address);

    builder.enforce_equal(LinearCombination::from_variable(derived_address), LinearCombination::from_variable(address));

    builder.add_range_constraint(balance, 64);

    builder.build(5)
}

pub(super) fn build_transaction_auth_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let tx_hash = builder.alloc_input(Some("tx_hash"));
    let sender_address = builder.alloc_input(Some("sender_address"));
    let recipient_address = builder.alloc_input(Some("recipient_address"));
    let amount_commitment = builder.alloc_input(Some("amount_commitment"));

    let secret_key = builder.alloc_variable(Some("secret_key"));
    let amount = builder.alloc_variable(Some("amount"));
    let nonce = builder.alloc_variable(Some("nonce"));

    let tx_intermediate = builder.alloc_variable(Some("tx_intermediate"));
    builder.enforce_multiplication(sender_address, recipient_address, tx_intermediate);

    builder.enforce_equal(LinearCombination::from_variable(tx_intermediate), LinearCombination::from_variable(tx_hash));

    let derived_sender = builder.alloc_variable(Some("derived_sender"));
    builder.enforce_multiplication(secret_key, secret_key, derived_sender);

    let amount_commit_intermediate = builder.alloc_variable(Some("amount_commit_intermediate"));
    builder.enforce_multiplication(amount, nonce, amount_commit_intermediate);

    builder.enforce_equal(LinearCombination::from_variable(amount_commit_intermediate), LinearCombination::from_variable(amount_commitment));

    builder.add_range_constraint(amount, 64);

    builder.build(7)
}

pub(super) fn build_stealth_spend_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let stealth_address = builder.alloc_input(Some("stealth_address"));
    let spend_pubkey_commitment = builder.alloc_input(Some("spend_pubkey_commitment"));

    let spend_secret = builder.alloc_variable(Some("spend_secret"));
    let view_secret = builder.alloc_variable(Some("view_secret"));
    let ephemeral_secret = builder.alloc_variable(Some("ephemeral_secret"));

    let shared_secret = builder.alloc_variable(Some("shared_secret"));
    builder.enforce_multiplication(view_secret, ephemeral_secret, shared_secret);

    let stealth_derived = builder.alloc_variable(Some("stealth_derived"));
    builder.enforce_multiplication(spend_secret, shared_secret, stealth_derived);

    builder.enforce_equal(LinearCombination::from_variable(stealth_derived), LinearCombination::from_variable(stealth_address));

    let commitment_intermediate = builder.alloc_variable(Some("commitment_intermediate"));
    builder.enforce_multiplication(spend_secret, spend_secret, commitment_intermediate);
    builder.enforce_equal(LinearCombination::from_variable(commitment_intermediate), LinearCombination::from_variable(spend_pubkey_commitment));

    builder.build(6)
}

pub(super) fn build_balance_sufficiency_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let minimum_required = builder.alloc_input(Some("minimum_required"));
    let balance_commitment = builder.alloc_input(Some("balance_commitment"));

    let actual_balance = builder.alloc_variable(Some("actual_balance"));
    let blinding_factor = builder.alloc_variable(Some("blinding_factor"));
    let difference = builder.alloc_variable(Some("difference"));

    let commit_intermediate = builder.alloc_variable(Some("commit_intermediate"));
    builder.enforce_multiplication(actual_balance, blinding_factor, commit_intermediate);
    builder.enforce_equal(LinearCombination::from_variable(commit_intermediate), LinearCombination::from_variable(balance_commitment));

    let mut diff_lc = LinearCombination::from_variable(actual_balance);
    diff_lc.add_term(minimum_required, FieldElement::zero().sub(&FieldElement::one()));
    builder.enforce_equal(LinearCombination::from_variable(difference), diff_lc);

    builder.add_range_constraint(difference, 64);

    builder.build(5)
}
