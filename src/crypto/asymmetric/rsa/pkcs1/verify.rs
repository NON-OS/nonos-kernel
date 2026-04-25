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

use super::super::keys::{rsa_public_operation, RsaPublicKey};
use super::digest::{
    pkcs1_digest_info_sha256, pkcs1_digest_info_sha256_no_null, pkcs1_digest_info_sha384,
    pkcs1_digest_info_sha384_no_null, pkcs1_digest_info_sha512, pkcs1_digest_info_sha512_no_null,
};
use super::padding::pkcs1_unpad_type1;
use crate::crypto::hash::sha256;
use crate::crypto::hash::sha384::sha384;
use crate::crypto::hash::sha512::sha512;
use crate::crypto::util::bigint::BigUint;

pub fn verify_pkcs1v15(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let hash = sha256(message);
    let em_len = public_key.bits / 8;
    let decrypted = match rsa_public_operation(&BigUint::from_bytes_be(signature), public_key) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let raw = decrypted.to_bytes_be();
    let mut decrypted_bytes = raw;
    if decrypted_bytes.len() < em_len {
        let mut padded = alloc::vec![0u8; em_len];
        padded[em_len - decrypted_bytes.len()..].copy_from_slice(&decrypted_bytes);
        decrypted_bytes = padded;
    }
    let unpadded = match pkcs1_unpad_type1(&decrypted_bytes) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let expected_with_null = pkcs1_digest_info_sha256(&hash);
    let expected_no_null = pkcs1_digest_info_sha256_no_null(&hash);
    if unpadded == expected_with_null || unpadded == expected_no_null {
        return true;
    }
    if unpadded.len() >= 32 {
        let sig_hash = &unpadded[unpadded.len() - 32..];
        if sig_hash == hash.as_slice() {
            let sha256_oid_bytes: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
            if unpadded[..unpadded.len() - 32].windows(9).any(|w| w == sha256_oid_bytes) {
                return true;
            }
        }
    }
    false
}

pub fn verify_pkcs1v15_sha384(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let hash = sha384(message);
    verify_pkcs1v15_with_digest(
        public_key,
        &hash,
        signature,
        &pkcs1_digest_info_sha384(&hash),
        &pkcs1_digest_info_sha384_no_null(&hash),
    )
}

pub fn verify_pkcs1v15_sha512(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let hash = sha512(message);
    verify_pkcs1v15_with_digest(
        public_key,
        &hash,
        signature,
        &pkcs1_digest_info_sha512(&hash),
        &pkcs1_digest_info_sha512_no_null(&hash),
    )
}

fn verify_pkcs1v15_with_digest(
    public_key: &RsaPublicKey,
    hash: &[u8],
    signature: &[u8],
    expected_with_null: &[u8],
    expected_no_null: &[u8],
) -> bool {
    let em_len = public_key.bits / 8;
    let decrypted = match rsa_public_operation(&BigUint::from_bytes_be(signature), public_key) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let raw = decrypted.to_bytes_be();
    let mut decrypted_bytes = raw;
    if decrypted_bytes.len() < em_len {
        let mut padded = alloc::vec![0u8; em_len];
        padded[em_len - decrypted_bytes.len()..].copy_from_slice(&decrypted_bytes);
        decrypted_bytes = padded;
    }
    let unpadded = match pkcs1_unpad_type1(&decrypted_bytes) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if unpadded == expected_with_null || unpadded == expected_no_null {
        return true;
    }
    if unpadded.len() >= hash.len() && &unpadded[unpadded.len() - hash.len()..] == hash {
        return true;
    }
    false
}

pub fn verify_signature(msg: &[u8], sig: &[u8], key: &RsaPublicKey) -> bool {
    verify_pkcs1v15(key, msg, sig)
}
