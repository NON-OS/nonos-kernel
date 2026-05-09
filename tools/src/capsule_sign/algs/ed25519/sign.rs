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

use ed25519_dalek::{Signer as _, SigningKey};

use crate::algs::traits::{KeyPair, Signer, Verifier};
use crate::error::SignError;

use super::{keygen, verify};

pub struct Ed25519;

impl Signer for Ed25519 {
    fn keygen_from_seed(seed: &[u8]) -> Result<KeyPair, SignError> {
        keygen::from_seed(seed)
    }

    fn keygen_random() -> Result<KeyPair, SignError> {
        keygen::random()
    }

    fn sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, SignError> {
        if seed.len() != 32 {
            return Err(SignError::InvalidSeedLength {
                alg: "ed25519",
                expected: 32,
                actual: seed.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(seed);
        let sk = SigningKey::from_bytes(&bytes);
        Ok(sk.sign(msg).to_bytes().to_vec())
    }
}

impl Verifier for Ed25519 {
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, SignError> {
        verify::raw(pubkey, msg, sig)
    }
}
