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

use super::types::ZkProof;

#[inline]
pub fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut x = 0u8;
    for i in 0..32 {
        x |= a[i] ^ b[i];
    }
    x == 0
}

#[cfg(feature = "zk-zeroize")]
pub fn zeroize_proof(p: &mut ZkProof) {
    use zeroize::Zeroize;
    p.proof_blob.zeroize();
    p.public_inputs.zeroize();
    if let Some(m) = &mut p.manifest {
        m.zeroize();
    }
}

#[cfg(not(feature = "zk-zeroize"))]
pub fn zeroize_proof(_p: &mut ZkProof) {}
