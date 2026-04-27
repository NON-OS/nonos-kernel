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

use super::state::get_zk_engine;
use crate::zk_engine::circuit::Constraint;
use crate::zk_engine::types::{ZKError, ZKProof};
use alloc::vec::Vec;

pub fn compile_circuit(constraints: Vec<Constraint>, num_witnesses: usize) -> Result<u32, ZKError> {
    get_zk_engine()?.compile_circuit(constraints, num_witnesses)
}

pub fn generate_proof(
    circuit_id: u32,
    witness: Vec<Vec<u8>>,
    public_inputs: Vec<Vec<u8>>,
) -> Result<ZKProof, ZKError> {
    get_zk_engine()?.generate_proof(circuit_id, witness, public_inputs)
}

pub fn verify_proof(proof: &ZKProof) -> Result<bool, ZKError> {
    get_zk_engine()?.verify_proof(proof)
}
