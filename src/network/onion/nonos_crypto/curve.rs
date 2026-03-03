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


use crate::crypto::{curve25519, sig};
use crate::network::onion::OnionError;

pub struct RealCurve25519;

impl RealCurve25519 {
    pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), OnionError> {
        curve25519::x25519_keypair().map_err(|_| OnionError::CryptoError)
    }

    pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
        curve25519::derive_public_key(private)
    }

    pub fn scalar_mult(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
        curve25519::compute_shared_secret(secret, peer_public)
    }
}

pub fn scalar_mult_x25519(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    curve25519::compute_shared_secret(secret, peer_public)
}

pub fn x25519_keypair() -> Result<([u8; 32], [u8; 32]), OnionError> {
    curve25519::x25519_keypair().map_err(|_| OnionError::CryptoError)
}

pub fn x25519(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    curve25519::compute_shared_secret(private, public)
}

pub struct RealEd25519;

impl RealEd25519 {
    pub fn keypair_from_seed(_seed32: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        match sig::generate_keypair(sig::SignatureAlgorithm::Ed25519) {
            Ok((private, public)) => {
                let mut priv_key = [0u8; 32];
                let mut pub_key = [0u8; 32];
                if private.len() >= 32 {
                    priv_key.copy_from_slice(&private[..32]);
                }
                if public.len() >= 32 {
                    pub_key.copy_from_slice(&public[..32]);
                }
                (priv_key, pub_key)
            }
            Err(_) => ([0u8; 32], [0u8; 32]),
        }
    }

    pub fn public_key(private_seed32: &[u8; 32]) -> [u8; 32] {
        sig::ed25519::scalar_mult_base(private_seed32).unwrap_or([0u8; 32])
    }

    pub fn sign(message: &[u8], private_seed32: &[u8; 32]) -> [u8; 64] {
        let keypair = crate::crypto::ed25519::KeyPair {
            private: *private_seed32,
            public: curve25519::derive_public_key(private_seed32),
        };
        let signature = crate::crypto::ed25519::sign(&keypair, message);
        signature.to_bytes()
    }

    pub fn verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
        let sig = crate::crypto::ed25519::Signature::from_bytes(signature);
        crate::crypto::ed25519::verify(public_key, message, &sig)
    }
}

pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, OnionError> {
    if public_key.len() != 32 || signature.len() != 64 {
        return Ok(false);
    }
    let mut pk = [0u8; 32];
    let mut sig = [0u8; 64];
    pk.copy_from_slice(public_key);
    sig.copy_from_slice(signature);

    let ed_sig = crate::crypto::ed25519::Signature::from_bytes(&sig);
    Ok(crate::crypto::ed25519::verify(&pk, message, &ed_sig))
}
