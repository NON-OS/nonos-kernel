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
use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub trait TlsCrypto: Sync + Send {
    fn random(&self, out32: &mut [u8; 32]) -> Result<(), OnionError>;
    fn sha256(&self, data: &[u8], out32: &mut [u8; 32]);
    fn sha384(&self, data: &[u8], out48: &mut [u8; 48]);
    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]);
    fn hmac_sha384(&self, key: &[u8], data: &[u8], out48: &mut [u8; 48]);
    fn hkdf_extract(&self, salt: &[u8; 32], ikm: &[u8; 32], out32: &mut [u8; 32]);
    fn hkdf_extract_384(&self, salt: &[u8], ikm: &[u8], out48: &mut [u8; 48]);
    fn hkdf_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]);
    fn hkdf_expand_384(&self, prk: &[u8], info: &[u8], out: &mut [u8]);
    fn x25519_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError>;
    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError>;
    fn aead_seal(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OnionError>;
    fn aead_open(
        &self,
        suite: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OnionError>;
    fn verify_ed25519(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_rsa_pss_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_rsa_pss_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_rsa_pkcs1v15_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_rsa_pkcs1v15_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_ecdsa_p256_sha256(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn verify_ecdsa_p384_sha384(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn p256_keypair(&self) -> Result<([u8; 32], [u8; 65]), OnionError>;
    fn p256_ecdh(&self, sk: &[u8; 32], peer_pub: &[u8; 65]) -> Result<[u8; 32], OnionError>;
}
