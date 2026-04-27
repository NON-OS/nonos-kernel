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
use super::keys::{PublicKey, SecretKey};
use crate::crypto::ed25519::KeyPair;
use alloc::vec::Vec;

pub type Signature = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    InvalidKey,
    SigningFailed,
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let kp = KeyPair::generate();
    let public = kp.public;
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&kp.private);
    secret[32..].copy_from_slice(&public);
    (public, secret)
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> (PublicKey, SecretKey) {
    let kp = KeyPair::from_seed(*seed);
    let public = kp.public;
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&kp.private);
    secret[32..].copy_from_slice(&public);
    (public, secret)
}

pub fn sign(message: &[u8], secret: &SecretKey) -> Result<Signature, SignError> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret[..32]);
    let kp = KeyPair::from_seed(seed);
    let sig = crate::crypto::ed25519::sign(&kp, message);
    Ok(sig.to_bytes())
}

pub fn sign_capsule(data: &[u8], secret: &SecretKey) -> Result<Vec<u8>, SignError> {
    let sig = sign(data, secret)?;
    let mut signed = data.to_vec();
    signed.extend_from_slice(&sig);
    Ok(signed)
}
