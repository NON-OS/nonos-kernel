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

use crate::crypto::constant_time::ct_eq_16;
use crate::crypto::symmetric::aes::Aes128;

use super::gcm::{aes128_ctr_gcm, compute_tag_128, derive_j0};
use super::ghash::GhashKey;
use super::TAG_SIZE;

pub struct Aes128Gcm {
    aes: Aes128,
    ghash_key: GhashKey,
}

impl Aes128Gcm {
    pub fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key);
        let ghash_key = GhashKey::new_128(&aes);
        Self { aes, ghash_key }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let j0 = derive_j0(nonce);

        let mut ciphertext = plaintext.to_vec();
        aes128_ctr_gcm(&self.aes, &j0, &mut ciphertext);

        let tag = compute_tag_128(&self.aes, &self.ghash_key, &j0, aad, &ciphertext);

        ciphertext.extend_from_slice(&tag);
        ciphertext
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err("ciphertext too short");
        }

        let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(ct_len);

        let j0 = derive_j0(nonce);

        let expected_tag = compute_tag_128(&self.aes, &self.ghash_key, &j0, aad, ciphertext);

        let tag_array: [u8; 16] = tag.try_into().map_err(|_| "invalid tag length")?;
        let tag_valid = ct_eq_16(&expected_tag, &tag_array);

        let mut plaintext = ciphertext.to_vec();
        aes128_ctr_gcm(&self.aes, &j0, &mut plaintext);

        if !tag_valid {
            secure_zero_slice(&mut plaintext);
            return Err("authentication failed");
        }

        Ok(plaintext)
    }

    pub fn encrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let j0 = derive_j0(nonce);
        aes128_ctr_gcm(&self.aes, &j0, buffer);
        compute_tag_128(&self.aes, &self.ghash_key, &j0, aad, buffer)
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), &'static str> {
        let j0 = derive_j0(nonce);

        let expected_tag = compute_tag_128(&self.aes, &self.ghash_key, &j0, aad, buffer);
        let tag_valid = ct_eq_16(&expected_tag, tag);

        aes128_ctr_gcm(&self.aes, &j0, buffer);

        if !tag_valid {
            secure_zero_slice(buffer);
            return Err("authentication failed");
        }

        Ok(())
    }
}

fn secure_zero_slice(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

pub fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let gcm = Aes128Gcm::new(key);
    Ok(gcm.encrypt(nonce, aad, plaintext))
}

pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let gcm = Aes128Gcm::new(key);
    gcm.decrypt(nonce, aad, ciphertext_and_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nist_case_1_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let pt: &[u8] = &[];

        let expected_tag: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];

        let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(&ct[..], &expected_tag[..]);

        let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec.len(), 0);
    }

    #[test]
    fn test_nist_case_2_one_block() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let pt = [0u8; 16];

        let expected_ct: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let expected_tag: [u8; 16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
            0xbd, 0xdf,
        ];

        let result = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
        assert_eq!(result.len(), 32);

        let ct = &result[..16];
        let tag = &result[16..];
        assert_eq!(ct, &expected_ct[..]);
        assert_eq!(tag, &expected_tag[..]);

        let dec = aes128_gcm_decrypt(&key, &nonce, aad, &result).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x24u8; 12];
        let aad = b"additional authenticated data";
        let pt = b"secret message to encrypt";

        let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);

        let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec, pt);
    }
}
