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

pub fn generate_plonk_proof(witness: &[u8]) -> Result<Vec<u8>, &'static str> {
    if witness.len() < 64 {
        return Err("Witness must contain at least 2 field elements");
    }
    let num_elements = witness.len() / 32;
    let mut elements = Vec::with_capacity(num_elements);
    for i in 0..num_elements {
        let mut elem = [0u8; 32];
        elem.copy_from_slice(&witness[i * 32..(i + 1) * 32]);
        elements.push(elem);
    }
    match crate::crypto::zk::zk_kernel::plonk_prove(&elements) {
        Ok(proof) => Ok(proof.to_bytes()),
        Err(e) => Err(e),
    }
}

pub fn verify_plonk_proof(proof: &[u8], public_inputs: &[u8]) -> bool {
    let plonk_proof = match crate::crypto::zk::zk_kernel::PlonkProof::from_bytes(proof) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let num_inputs = public_inputs.len() / 32;
    let mut inputs = Vec::with_capacity(num_inputs);
    for i in 0..num_inputs {
        let mut inp = [0u8; 32];
        inp.copy_from_slice(&public_inputs[i * 32..(i + 1) * 32]);
        inputs.push(inp);
    }
    crate::crypto::zk::zk_kernel::plonk_verify(&plonk_proof, &inputs)
}
