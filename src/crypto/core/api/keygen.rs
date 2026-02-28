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

use crate::crypto::asymmetric::ed25519;
use super::types::SignatureAlgorithm;

pub fn generate_keypair(algorithm: SignatureAlgorithm) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let keypair = ed25519::KeyPair::generate();
            Ok((keypair.public.to_vec(), keypair.private.to_vec()))
        },
        SignatureAlgorithm::EcdsaP256 => {
            let (sk, pk) = crate::crypto::asymmetric::p256::generate_keypair();
            Ok((pk.to_vec(), sk.to_vec()))
        },
        SignatureAlgorithm::Rsa2048 => {
            match crate::crypto::asymmetric::rsa::generate_keypair_with_bits(2048) {
                Ok((public_key, private_key)) => {
                    let pk = public_key.n.to_bytes_be();
                    let sk = private_key.d.to_bytes_be();
                    Ok((pk, sk))
                },
                Err(_) => Err("RSA key generation failed"),
            }
        },
    }
}

pub mod sig {
    pub use super::generate_keypair;
    pub use super::super::SignatureAlgorithm;
    pub use super::super::verify::ed25519_verify;

    pub mod ed25519 {
        pub use crate::crypto::asymmetric::ed25519::{verify as verify_signature, Signature as Ed25519Signature};

        pub fn scalar_mult_base(scalar: &[u8; 32]) -> Result<[u8; 32], &'static str> {
            let kp = crate::crypto::asymmetric::ed25519::KeyPair::from_seed(*scalar);
            Ok(kp.public)
        }
    }
}
