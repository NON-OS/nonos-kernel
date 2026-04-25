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

use crate::zk_engine::circuit::{Circuit, CircuitBuilder, LinearCombination};
use crate::zk_engine::groth16::FieldElement;
use crate::zk_engine::ZKError;

pub(super) fn build_balance_ownership_circuit() -> Result<Circuit, ZKError> {
    let mut b = CircuitBuilder::new();
    let com = b.alloc_input(Some("commitment_hash"));
    let addr = b.alloc_input(Some("address"));
    let bal = b.alloc_variable(Some("balance"));
    let blind = b.alloc_variable(Some("blinding_factor"));
    let sk = b.alloc_variable(Some("secret_key"));
    let hash_int = b.alloc_variable(Some("hash_intermediate"));
    b.enforce_multiplication(bal, blind, hash_int);
    let mut lc = LinearCombination::from_variable(bal);
    lc.add_term(blind, FieldElement::one());
    b.enforce_equal(LinearCombination::from_variable(com), lc);
    let derived = b.alloc_variable(Some("derived_address"));
    b.enforce_multiplication(sk, sk, derived);
    b.enforce_equal(
        LinearCombination::from_variable(derived),
        LinearCombination::from_variable(addr),
    );
    b.add_range_constraint(bal, 64);
    b.build(5)
}

pub(super) use super::zk_circuit_adv::build_stealth_spend_circuit;
