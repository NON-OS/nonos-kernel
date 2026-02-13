// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::zk::verify::ct_eq32;

pub fn derive_circuit_key(
    program_hash: &[u8; 32],
    proof_commitment: &[u8; 32],
    context: &[u8],
) -> [u8; 32] {
    use blake3::Hasher;
    let mut hasher = Hasher::new_derive_key("NONOS:CIRCUIT_KEY:v1");
    hasher.update(program_hash);
    hasher.update(proof_commitment);
    hasher.update(context);
    *hasher.finalize().as_bytes()
}

pub fn verify_circuit_key_derivation(
    expected_key: &[u8; 32],
    program_hash: &[u8; 32],
    proof_commitment: &[u8; 32],
    context: &[u8],
) -> bool {
    let derived = derive_circuit_key(program_hash, proof_commitment, context);
    ct_eq32(expected_key, &derived)
}
