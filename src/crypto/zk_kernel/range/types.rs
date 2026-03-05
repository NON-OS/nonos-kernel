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

#[derive(Clone, Debug)]
pub(crate) struct BitProof {
    pub(crate) e0: [u8; 32],
    pub(crate) e1: [u8; 32],
    pub(crate) z0: [u8; 32],
    pub(crate) z1: [u8; 32],
}

impl BitProof {
    pub(crate) fn new(e0: [u8; 32], e1: [u8; 32], z0: [u8; 32], z1: [u8; 32]) -> Self {
        Self { e0, e1, z0, z1 }
    }

    pub(crate) fn challenge_sum(&self) -> [u8; 32] {
        use super::super::field::FieldElement;
        let e0_fe = FieldElement::from_bytes(&self.e0);
        let e1_fe = FieldElement::from_bytes(&self.e1);
        e0_fe.add(&e1_fe).to_bytes()
    }

    pub(crate) fn verify_structure(&self) -> bool {
        let z0_nonzero = self.z0 != [0u8; 32];
        let z1_nonzero = self.z1 != [0u8; 32];
        z0_nonzero || z1_nonzero
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RangeProof {
    pub(crate) bit_commitments: Vec<[u8; 32]>,
    pub(crate) bit_blindings: Vec<[u8; 32]>,
    pub(crate) bit_proofs: Vec<BitProof>,
    pub(crate) response: [u8; 32],
    pub(crate) bits: u8,
}
