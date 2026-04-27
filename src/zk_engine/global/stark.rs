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
use alloc::vec;
use alloc::vec::Vec;

pub fn generate_stark_proof(
    circuit_id: u32,
    witness: Vec<Vec<u8>>,
    public_inputs: Vec<Vec<u8>>,
) -> Result<Vec<u8>, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.generate_proof(circuit_id, witness, public_inputs) {
        Ok(proof) => {
            let mut stark_proof = vec![0x53, 0x54, 0x41, 0x52];
            stark_proof.extend(engine.serialize_proof(&proof));
            Ok(stark_proof)
        }
        Err(_) => Err("Failed to generate STARK proof"),
    }
}

pub fn verify_stark_proof(proof_data: &[u8]) -> Result<bool, &'static str> {
    if proof_data.len() < 4 || &proof_data[0..4] != b"STAR" {
        return Err("Invalid STARK proof format");
    }
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.deserialize_proof(&proof_data[4..]) {
        Ok(proof) => match engine.verify_proof(&proof) {
            Ok(valid) => Ok(valid),
            Err(_) => Err("Failed to verify STARK proof"),
        },
        Err(_) => Err("Invalid STARK proof format"),
    }
}
