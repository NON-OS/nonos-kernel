// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::crypto::constant_time::ct_eq_16;
use crate::crypto::symmetric::aes::Aes256;

use super::ghash::{GhashKey, GhashState, u128_to_block};
use super::gcm::{aes_ctr_gcm, compute_tag, derive_j0};
use super::TAG_SIZE;

pub struct Aes256Gcm {
    aes: Aes256,
    ghash_key: GhashKey,
}

impl Aes256Gcm {
    pub fn new(key: &[u8; 32]) -> Self {
        let aes = Aes256::new(key);
        let ghash_key = GhashKey::new(&aes);
        Self { aes, ghash_key }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let j0 = derive_j0(nonce);
        let mut ciphertext = plaintext.to_vec();
        aes_ctr_gcm(&self.aes, &j0, &mut ciphertext);

        let tag = compute_tag(&self.aes, &self.ghash_key, &j0, aad, &ciphertext);
        ciphertext.extend_from_slice(&tag);
        ciphertext
    }

    // SECURITY: Constant-time decrypt - always performs decryption to prevent timing oracle
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err("ciphertext too short");
        }

        let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(ct_len);
        let j0 = derive_j0(nonce);
        let expected_tag = compute_tag(&self.aes, &self.ghash_key, &j0, aad, ciphertext);
        let tag_array: [u8; 16] = tag.try_into().map_err(|_| "invalid tag length")?;
        let tag_valid = ct_eq_16(&expected_tag, &tag_array);
        // SECURITY: Always decrypt regardless of tag validity to prevent timing oracle
        let mut plaintext = ciphertext.to_vec();
        aes_ctr_gcm(&self.aes, &j0, &mut plaintext);
        if !tag_valid {
            // SECURITY: Zero plaintext to prevent leaking decrypted data on auth failure
            secure_zero_slice(&mut plaintext);
            return Err("authentication failed");
        }

        Ok(plaintext)
    }

    pub fn encrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let j0 = derive_j0(nonce);

        aes_ctr_gcm(&self.aes, &j0, buffer);

        compute_tag(&self.aes, &self.ghash_key, &j0, aad, buffer)
    }

    // SECURITY: Constant-time decrypt_in_place - always performs decryption to prevent timing oracle
    pub fn decrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8], tag: &[u8; 16]) -> Result<(), &'static str> {
        let j0 = derive_j0(nonce);

        let expected_tag = compute_tag(&self.aes, &self.ghash_key, &j0, aad, buffer);
        let tag_valid = ct_eq_16(&expected_tag, tag);

        // SECURITY: Always decrypt regardless of tag validity to prevent timing oracle
        aes_ctr_gcm(&self.aes, &j0, buffer);

        if !tag_valid {
            // SECURITY: Zero buffer to prevent leaking decrypted data on auth failure
            secure_zero_slice(buffer);
            return Err("authentication failed");
        }

        Ok(())
    }
}

// SECURITY: Volatile zeroing to prevent compiler from optimizing away
fn secure_zero_slice(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let gcm = Aes256Gcm::new(key);
    Ok(gcm.encrypt(nonce, aad, plaintext))
}

pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let gcm = Aes256Gcm::new(key);
    gcm.decrypt(nonce, aad, ciphertext_and_tag)
}
