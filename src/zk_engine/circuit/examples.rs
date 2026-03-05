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

//! Example circuits for testing.

use super::core::{Circuit, LinearCombination};
use super::builder::CircuitBuilder;
use crate::zk_engine::ZKError;

/// Create a simple multiplication circuit: x * y = z
pub fn multiplication_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let x = builder.alloc_input(Some("x"));
    let y = builder.alloc_input(Some("y"));
    let z = builder.alloc_variable(Some("z"));

    builder.enforce_multiplication(x, y, z);

    builder.build(1)
}

/// Create a hash preimage circuit
pub fn hash_preimage_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let preimage = builder.alloc_input(Some("preimage"));
    let hash = builder.alloc_input(Some("hash"));
    let temp = builder.alloc_variable(Some("temp"));

    builder.enforce_multiplication(preimage, preimage, temp);

    builder.enforce_equal(
        LinearCombination::from_variable(temp),
        LinearCombination::from_variable(hash)
    );

    builder.build(1)
}

/// Create a range proof circuit (prove x is in [0, 2^bits))
pub fn range_proof_circuit(bits: usize) -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();

    let x = builder.alloc_input(Some("x"));
    builder.add_range_constraint(x, bits);

    builder.build(1)
}
