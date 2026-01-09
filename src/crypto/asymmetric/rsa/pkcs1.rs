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

use alloc::vec::Vec;
use crate::crypto::hash::sha256;
use crate::crypto::util::bigint::BigUint;
use crate::crypto::{CryptoError, CryptoResult};
use super::keys::{RsaPrivateKey, RsaPublicKey, rsa_private_operation, rsa_public_operation};

pub fn sign_pkcs1v15(private_key: &RsaPrivateKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
    let hash = sha256(message);
    let digest_info = pkcs1_digest_info_sha256(&hash);

    let padded = pkcs1_pad_type1(&digest_info, private_key.bits / 8)?;
    let signature = rsa_private_operation(&BigUint::from_bytes_be(&padded), private_key)?;

    Ok(signature.to_bytes_be())
}

pub fn verify_pkcs1v15(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let hash = sha256(message);
    let expected_digest_info = pkcs1_digest_info_sha256(&hash);
    if let Ok(decrypted) = rsa_public_operation(&BigUint::from_bytes_be(signature), public_key) {
        let decrypted_bytes = decrypted.to_bytes_be();
        if let Ok(unpadded) = pkcs1_unpad_type1(&decrypted_bytes) {
            return unpadded == expected_digest_info;
        }
    }

    false
}

fn pkcs1_pad_type1(data: &[u8], em_len: usize) -> CryptoResult<Vec<u8>> {
    if data.len() > em_len - 11 {
        return Err(CryptoError::InvalidLength);
    }

    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.push(0x01);

    let ps_len = em_len - data.len() - 3;
    for _ in 0..ps_len {
        em.push(0xFF);
    }

    em.push(0x00);
    em.extend_from_slice(data);

    Ok(em)
}

// SECURITY: Constant-time PKCS#1 v1.5 unpadding to prevent Bleichenbacher attack
// All operations are performed regardless of padding validity
fn pkcs1_unpad_type1(em: &[u8]) -> CryptoResult<Vec<u8>> {
    if em.len() < 11 {
        // Length check is public information (ciphertext length)
        return Err(CryptoError::InvalidLength);
    }

    // Accumulate validity flags - no early returns
    let mut valid: u8 = 1;

    // Check header bytes (constant-time)
    valid &= ct_eq_u8(em[0], 0x00);
    valid &= ct_eq_u8(em[1], 0x01);

    // Find separator and validate padding in constant time
    let mut sep_idx: usize = 0;
    let mut found_sep: u8 = 0;
    let mut invalid_padding: u8 = 0;
    for i in 2..em.len() {
        let is_zero = ct_eq_u8(em[i], 0x00);
        let is_ff = ct_eq_u8(em[i], 0xFF);
        // Update sep_idx only on first zero (when found_sep is still 0)
        let should_update = is_zero & (1 ^ found_sep);
        sep_idx = ct_select_usize(should_update, i, sep_idx);
        // Mark that we found separator
        found_sep |= is_zero;
        // If we haven't found separator yet and byte is not 0xFF, invalid
        let in_padding = 1 ^ found_sep;
        invalid_padding |= in_padding & (1 ^ is_ff) & (1 ^ is_zero);
    }

    // Must have found separator and padding must be valid
    valid &= found_sep;
    valid &= 1 ^ invalid_padding;

    // Separator must be at least at index 10 (8 bytes of 0xFF minimum)
    // SECURITY: Constant-time comparison
    let sep_ok = ct_ge_usize(sep_idx, 10);
    valid &= sep_ok;

    if valid == 0 {
        return Err(CryptoError::InvalidLength);
    }

    Ok(em[sep_idx + 1..].to_vec())
}

#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    let is_zero = (diff as u16 | (diff as u16).wrapping_neg()) >> 8;
    (1 ^ is_zero) as u8
}

#[inline]
fn ct_select_usize(mask: u8, a: usize, b: usize) -> usize {
    let m = (mask as usize).wrapping_neg() & usize::MAX;
    (a & m) | (b & !m)
}

// SECURITY: Constant-time greater-than-or-equal comparison for usize
#[inline]
fn ct_ge_usize(a: usize, b: usize) -> u8 {
    // Return 1 if a >= b, 0 if a < b, constant-time
    // Uses the formula: borrow = ((~a & b) | ((~a | b) & diff)) >> (BITS - 1)
    let diff = a.wrapping_sub(b);
    let a_inv = !a;
    let borrow = ((a_inv & b) | ((a_inv | b) & diff)) >> (usize::BITS - 1);
    (1 ^ (borrow as u8)) // 1 if no borrow (a >= b), 0 if borrow (a < b)
}

fn pkcs1_digest_info_sha256(hash: &[u8]) -> Vec<u8> {
    let mut digest_info = Vec::new();
    let sha256_oid = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    digest_info.extend_from_slice(&sha256_oid);
    digest_info.extend_from_slice(hash);

    digest_info
}

pub fn sign_message(msg: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>, &'static str> {
    sign_pkcs1v15(key, msg).map_err(|_| "RSA signing failed")
}

pub fn verify_signature(msg: &[u8], sig: &[u8], key: &RsaPublicKey) -> bool {
    verify_pkcs1v15(key, msg, sig)
}
