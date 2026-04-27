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

use super::super::types::CipherSuite;
use super::traits::TlsCrypto;
use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub struct KernelTlsCrypto;
pub static KERNEL_TLS_CRYPTO: KernelTlsCrypto = KernelTlsCrypto;

impl TlsCrypto for KernelTlsCrypto {
    fn random(&self, out32: &mut [u8; 32]) -> Result<(), OnionError> {
        crate::network::onion::nonos_crypto::rand32(out32).map_err(|_| OnionError::CryptoError)
    }

    fn sha256(&self, data: &[u8], out32: &mut [u8; 32]) {
        let _ = crate::network::onion::nonos_crypto::sha256(data, out32);
    }

    fn sha384(&self, data: &[u8], out48: &mut [u8; 48]) {
        let h = crate::crypto::hash::sha384::sha384(data);
        out48.copy_from_slice(&h);
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]) {
        match crate::network::onion::nonos_crypto::hmac_sha256(key, data) {
            Ok(result) => {
                let len = core::cmp::min(result.len(), 32);
                out32[..len].copy_from_slice(&result[..len]);
            }
            Err(_) => out32.fill(0),
        }
    }

    fn hmac_sha384(&self, key: &[u8], data: &[u8], out48: &mut [u8; 48]) {
        match crate::network::onion::nonos_crypto::hmac_sha384(key, data) {
            Ok(result) => out48.copy_from_slice(&result),
            Err(_) => out48.fill(0),
        }
    }

    fn hkdf_extract(&self, salt: &[u8; 32], ikm: &[u8; 32], out32: &mut [u8; 32]) {
        let _ = crate::network::onion::nonos_crypto::hkdf_extract_sha256(salt, ikm, out32);
    }

    fn hkdf_extract_384(&self, salt: &[u8], ikm: &[u8], out48: &mut [u8; 48]) {
        let _ = crate::network::onion::nonos_crypto::hkdf_extract_sha384(salt, ikm, out48);
    }

    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
        let _ = crate::network::onion::nonos_crypto::hkdf_expand_sha256(prk, info, out.len(), out);
    }

    fn hkdf_expand_384(&self, prk: &[u8], info: &[u8], out: &mut [u8]) {
        let _ = crate::network::onion::nonos_crypto::hkdf_expand_sha384(prk, info, out);
    }

    fn x25519_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError> {
        crate::network::onion::nonos_crypto::x25519_keypair().map_err(|_| OnionError::CryptoError)
    }

    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError> {
        Ok(crate::network::onion::nonos_crypto::scalar_mult_x25519(sk, pk))
    }

    fn aead_seal(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        match suite {
            CipherSuite::TlsAes128GcmSha256 => {
                crate::network::onion::nonos_crypto::tls_aes128_gcm_seal(key, nonce, aad, plaintext)
            }
            CipherSuite::TlsAes256GcmSha384 => {
                crate::network::onion::nonos_crypto::tls_aes256_gcm_seal(key, nonce, aad, plaintext)
            }
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                crate::network::onion::nonos_crypto::tls_chacha20poly1305_seal(
                    key, nonce, aad, plaintext,
                )
            }
        }
        .map_err(|_| OnionError::CryptoError)
    }

    fn aead_open(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        match suite {
            CipherSuite::TlsAes128GcmSha256 => {
                crate::network::onion::nonos_crypto::tls_aes128_gcm_open(
                    key, nonce, aad, ciphertext,
                )
            }
            CipherSuite::TlsAes256GcmSha384 => {
                crate::network::onion::nonos_crypto::tls_aes256_gcm_open(
                    key, nonce, aad, ciphertext,
                )
            }
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                crate::network::onion::nonos_crypto::tls_chacha20poly1305_open(
                    key, nonce, aad, ciphertext,
                )
            }
        }
        .map_err(|_| OnionError::CryptoError)
    }

    fn verify_ed25519(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::ed25519_verify(pubkey, msg, sig).unwrap_or(false)
    }

    fn verify_rsa_pss_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::rsa_pss_sha256_verify_spki(spki_der, msg, sig)
            .unwrap_or(false)
    }

    fn verify_rsa_pss_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::rsa_pss_sha384_verify_spki(spki_der, msg, sig)
            .unwrap_or(false)
    }

    fn verify_rsa_pkcs1v15_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::rsa_pkcs1v15_sha256_verify_spki(spki_der, msg, sig)
            .unwrap_or(false)
    }

    fn verify_rsa_pkcs1v15_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::rsa_pkcs1v15_sha384_verify_spki(spki_der, msg, sig)
            .unwrap_or(false)
    }

    fn verify_ecdsa_p256_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::ecdsa_p256_sha256_verify_spki(spki_der, msg, sig)
            .unwrap_or(false)
    }

    fn verify_ecdsa_p384_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::network::onion::nonos_crypto::ecdsa_p384_sha384_verify_spki(spki_der, msg, sig)
            .unwrap_or(false)
    }

    fn p256_keypair(&self) -> Result<([u8; 32], [u8; 65]), OnionError> {
        let (sk, pk) = crate::crypto::asymmetric::p256::ecdh::p256_ecdh_keypair();
        let mut pk65 = [0u8; 65];
        pk65.copy_from_slice(&pk);
        Ok((sk, pk65))
    }

    fn p256_ecdh(&self, sk: &[u8; 32], peer_pub: &[u8; 65]) -> Result<[u8; 32], OnionError> {
        crate::crypto::asymmetric::p256::ecdh::p256_ecdh(sk, peer_pub)
            .ok_or(OnionError::CryptoError)
    }
}
