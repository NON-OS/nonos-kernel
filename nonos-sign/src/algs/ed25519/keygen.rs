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

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::algs::traits::KeyPair;
use crate::error::SignError;

pub fn from_seed(seed: &[u8]) -> Result<KeyPair, SignError> {
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
    let vk = sk.verifying_key();
    Ok(KeyPair { pubkey: vk.to_bytes().to_vec(), seed: bytes.to_vec() })
}

pub fn random() -> Result<KeyPair, SignError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    from_seed(&seed)
}
