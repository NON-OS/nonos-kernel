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

use crate::crypto::ed25519::{KeyPair, Signature as EdSig, sign as ed25519_sign, verify as ed25519_verify};
use super::constants::DOM_SCHNORR;

#[derive(Clone, Debug)]
pub struct SchnorrProof {
    pub commitment: [u8; 32],
    pub response: [u8; 32],
}

impl SchnorrProof {
    pub fn prove(secret_key: &[u8; 32], public_key: &[u8; 32]) -> Self {
        let keypair = KeyPair::from_seed(*secret_key);
        let mut message = [0u8; 64];
        message[..32].copy_from_slice(DOM_SCHNORR);
        message[32..].copy_from_slice(public_key);
        let sig = ed25519_sign(&keypair, &message);
        let sig_bytes = sig.to_bytes();
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 32];
        commitment.copy_from_slice(&sig_bytes[..32]);
        response.copy_from_slice(&sig_bytes[32..]);
        Self { commitment, response }
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        let mut message = [0u8; 64];
        message[..32].copy_from_slice(DOM_SCHNORR);
        message[32..].copy_from_slice(public_key);
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.commitment);
        sig_bytes[32..].copy_from_slice(&self.response);
        let sig = EdSig::from_bytes(&sig_bytes);
        ed25519_verify(public_key, &message, &sig)
    }
}
