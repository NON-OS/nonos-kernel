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

use super::range_types::RangeProof;

const MIN_PROOF_SIZE: usize = 32 * 7 + 4;

pub(super) fn parse_proof(proof: &[u8]) -> Option<RangeProof> {
    if proof.len() < MIN_PROOF_SIZE {
        return None;
    }
    let mut offset = 0;
    let mut a = [0u8; 32];
    a.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let mut s = [0u8; 32];
    s.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let mut t1 = [0u8; 32];
    t1.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let mut t2 = [0u8; 32];
    t2.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let mut tau_x = [0u8; 32];
    tau_x.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let mut mu = [0u8; 32];
    mu.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let mut inner_product = [0u8; 32];
    inner_product.copy_from_slice(&proof[offset..offset + 32]);
    offset += 32;
    let bit_length = u32::from_le_bytes([
        proof[offset],
        proof[offset + 1],
        proof[offset + 2],
        proof[offset + 3],
    ]);
    if bit_length == 0 || bit_length > 64 {
        return None;
    }
    Some(RangeProof { a, s, t1, t2, tau_x, mu, inner_product, bit_length })
}
