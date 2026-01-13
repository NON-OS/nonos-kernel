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

use crate::crypto::hash::blake3_hash;
use crate::crypto::ed25519::{KeyPair, Signature as EdSig, sign as ed25519_sign, verify as ed25519_verify};
use super::constants::DOM_SIGMA;

pub mod proof_types {
    pub const DLOG: u8 = 1;
    pub const EQUALITY: u8 = 2;
    pub const RANGE: u8 = 3;
    pub const MEMBERSHIP: u8 = 4;
}

#[derive(Clone, Debug)]
pub struct SigmaProof {
    pub a: [u8; 32],
    pub e: [u8; 32],
    pub z: [u8; 32],
    pub proof_type: u8,
}

impl SigmaProof {
    pub fn prove_dlog(witness: &[u8; 32], statement: &[u8; 32]) -> Self {
        let keypair = KeyPair::from_seed(*witness);
        let mut message = [0u8; 64];
        message[..32].copy_from_slice(DOM_SIGMA);
        message[32..].copy_from_slice(statement);
        let sig = ed25519_sign(&keypair, &message);
        let sig_bytes = sig.to_bytes();
        let mut a = [0u8; 32];
        let mut z = [0u8; 32];
        a.copy_from_slice(&sig_bytes[..32]);
        z.copy_from_slice(&sig_bytes[32..]);
        let e = blake3_hash(&message);
        Self { a, e, z, proof_type: proof_types::DLOG }
    }

    pub fn verify(&self, statement: &[u8; 32]) -> bool {
        match self.proof_type {
            proof_types::DLOG => {
                let mut message = [0u8; 64];
                message[..32].copy_from_slice(DOM_SIGMA);
                message[32..].copy_from_slice(statement);
                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(&self.a);
                sig_bytes[32..].copy_from_slice(&self.z);
                let sig = EdSig::from_bytes(&sig_bytes);
                ed25519_verify(statement, &message, &sig)
            }
            _ => false,
        }
    }
}
