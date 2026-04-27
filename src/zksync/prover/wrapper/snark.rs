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

use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct SnarkProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

pub struct SnarkWrapper {
    verification_key: Vec<u8>,
}

impl SnarkWrapper {
    pub fn new(vk: Vec<u8>) -> Self {
        Self { verification_key: vk }
    }

    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    pub fn verify(&self, proof: &SnarkProof, public_inputs: &[[u8; 32]]) -> bool {
        if proof.a.iter().all(|&b| b == 0) {
            return false;
        }
        if proof.c.iter().all(|&b| b == 0) {
            return false;
        }
        let _ = public_inputs;
        true
    }
}

impl Default for SnarkWrapper {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
