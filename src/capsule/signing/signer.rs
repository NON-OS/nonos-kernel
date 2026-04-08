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
use super::keys::{PublicKey, SecretKey};

pub type Signature = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError { InvalidKey, SigningFailed }

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let mut seed = [0u8; 32];
    crate::random::fill_bytes(&mut seed);
    keypair_from_seed(&seed)
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> (PublicKey, SecretKey) {
    let secret = ed25519_expand_key(seed);
    let public = ed25519_public_from_secret(&secret);
    (public, secret)
}

pub fn sign(message: &[u8], secret: &SecretKey) -> Result<Signature, SignError> {
    let public = ed25519_public_from_secret(secret);
    let sig = ed25519_sign(message, secret, &public);
    Ok(sig)
}

pub fn sign_capsule(data: &[u8], secret: &SecretKey) -> Result<Vec<u8>, SignError> {
    let sig = sign(data, secret)?;
    let mut signed = data.to_vec();
    signed.extend_from_slice(&sig);
    Ok(signed)
}

fn ed25519_expand_key(seed: &[u8; 32]) -> SecretKey {
    let hash = crate::crypto::sha512(seed);
    let mut secret = [0u8; 64];
    secret.copy_from_slice(&hash);
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    secret
}

fn ed25519_public_from_secret(secret: &SecretKey) -> PublicKey {
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&secret[0..32]);
    crate::crypto::ed25519::scalar_mult_base(&scalar)
}

fn ed25519_sign(message: &[u8], secret: &SecretKey, public: &PublicKey) -> Signature {
    crate::crypto::ed25519::sign(message, secret, public)
}
