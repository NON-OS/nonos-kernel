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


use alloc::{vec, vec::Vec};
use crate::crypto::{hash, entropy};
use crate::network::onion::OnionError;
use super::{RSAKeyPair, RealCurve25519, RealEd25519};
use super::kdf::{hmac_sha256, hkdf_extract_expand};

#[derive(Default)]
pub struct VaultRng;

impl VaultRng {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::crypto::fill_random_bytes(dest);
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }
}

pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    crate::crypto::fill_random_bytes(&mut seed);
    seed
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }

    result == 0
}

pub fn secure_memzero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

pub fn conditional_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    let mask = if condition { 0xFF } else { 0x00 };
    let mut result = vec![0u8; a.len().max(b.len())];

    for i in 0..result.len() {
        let a_byte = if i < a.len() { a[i] } else { 0 };
        let b_byte = if i < b.len() { b[i] } else { 0 };
        result[i] = (mask & a_byte) | (!mask & b_byte);
    }

    result
}

pub fn rand32(out: &mut [u8; 32]) -> Result<(), OnionError> {
    let entropy_bytes = entropy::get_entropy(32);
    out.copy_from_slice(&entropy_bytes[..32]);
    Ok(())
}

pub fn sha256(data: &[u8], out: &mut [u8; 32]) -> Result<(), OnionError> {
    let result = hash::sha256(data);
    out.copy_from_slice(&result);
    Ok(())
}

pub fn run_comprehensive_tests() -> Result<(), OnionError> {
    let rsa_keypair = RSAKeyPair::generate(2048)?;
    let test_data = b"test message for RSA";
    let signature = rsa_keypair.sign_pkcs1v15_sha256(test_data)?;
    let public_key = rsa_keypair.public();
    if !public_key.verify_pkcs1v15_sha256(test_data, &signature) {
        return Err(OnionError::CryptoError);
    }

    let (x25519_priv, x25519_pub) = RealCurve25519::generate_keypair()?;
    let derived_pub = RealCurve25519::public_key(&x25519_priv);
    if derived_pub != x25519_pub {
        return Err(OnionError::CryptoError);
    }

    let test_msg = b"test message for Ed25519";
    let (ed_priv, ed_pub) = RealEd25519::keypair_from_seed(&generate_seed());
    let ed_signature = RealEd25519::sign(test_msg, &ed_priv);
    if !RealEd25519::verify(test_msg, &ed_signature, &ed_pub) {
        return Err(OnionError::CryptoError);
    }

    let hmac_key = b"test key";
    let hmac_data = b"test data";
    let hmac_result = hmac_sha256(hmac_key, hmac_data)?;
    if hmac_result.len() != 32 {
        return Err(OnionError::CryptoError);
    }

    let hkdf_result = hkdf_extract_expand(b"secret", b"salt", b"info", 32)?;
    if hkdf_result.len() != 32 {
        return Err(OnionError::CryptoError);
    }

    Ok(())
}
