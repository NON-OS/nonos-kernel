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
use alloc::vec::Vec;

pub fn generate_groth16_proof(
    circuit_id: u32,
    witness: Vec<Vec<u8>>,
    public_inputs: Vec<Vec<u8>>,
) -> Result<Vec<u8>, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.generate_proof(circuit_id, witness, public_inputs) {
        Ok(proof) => Ok(engine.serialize_proof(&proof)),
        Err(_) => Err("Failed to generate Groth16 proof"),
    }
}

pub fn verify_groth16_proof(proof_data: &[u8]) -> Result<bool, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.deserialize_proof(proof_data) {
        Ok(proof) => match engine.verify_proof(&proof) {
            Ok(valid) => Ok(valid),
            Err(_) => Err("Failed to verify Groth16 proof"),
        },
        Err(_) => Err("Invalid proof format"),
    }
}
