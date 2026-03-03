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
use crate::crypto::rsa;
use crate::network::onion::OnionError;

#[derive(Clone)]
pub struct RSAKeyPair {
    pub(crate) inner: rsa::RsaPrivateKey,
}

#[derive(Clone)]
pub struct RSAPublic {
    pub(crate) inner: rsa::RsaPublicKey,
}

impl RSAKeyPair {
    pub fn generate(bits: usize) -> Result<Self, OnionError> {
        if bits < 2048 || bits % 8 != 0 {
            return Err(OnionError::CryptoError);
        }
        let (_, inner) = rsa::generate_keypair().map_err(|_| OnionError::CryptoError)?;
        Ok(Self { inner })
    }

    pub fn public(&self) -> RSAPublic {
        RSAPublic {
            inner: rsa::extract_public_key(&self.inner),
        }
    }

    pub fn sign_pkcs1v15_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, OnionError> {
        rsa::sign_message(msg, &self.inner).map_err(|_| OnionError::CryptoError)
    }

    pub fn sign_pss_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, OnionError> {
        rsa::sign_pss(msg, &self.inner).map_err(|_| OnionError::CryptoError)
    }

    pub fn decrypt_oaep_sha256(&self, ciphertext: &[u8], _label: Option<&[u8]>) -> Result<Vec<u8>, OnionError> {
        rsa::decrypt(ciphertext, &self.inner).map_err(|_| OnionError::CryptoError)
    }
}

impl RSAPublic {
    pub fn verify_pkcs1v15_sha256(&self, msg: &[u8], sig: &[u8]) -> bool {
        rsa::verify_signature(msg, sig, &self.inner)
    }

    pub fn encrypt_oaep_sha256(&self, plaintext: &[u8], _label: Option<&[u8]>) -> Result<Vec<u8>, OnionError> {
        rsa::encrypt(plaintext, &self.inner).map_err(|_| OnionError::CryptoError)
    }

    pub fn modulus_be(&self) -> Vec<u8> {
        self.inner.n.to_bytes_be()
    }

    pub fn exponent_be(&self) -> Vec<u8> {
        self.inner.e.to_bytes_be()
    }
}

pub type RealRSA = RSAKeyPair;
