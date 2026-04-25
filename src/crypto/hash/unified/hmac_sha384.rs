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

//! HMAC-SHA-384 (RFC 2104 with SHA-384).
//! Block size is 128 bytes (same as SHA-512). Output is 48 bytes.

use crate::crypto::constant_time;
use crate::crypto::hash::sha384::{sha384, Hash384};
use alloc::vec::Vec;

/// SHA-384 block size (same as SHA-512).
const BLOCK_SIZE: usize = 128;

pub fn hmac_sha384(key: &[u8], message: &[u8]) -> Hash384 {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hk = sha384(key);
        key_block[..48].copy_from_slice(&hk);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    constant_time::secure_zero(&mut key_block);

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha384(&inner);

    constant_time::secure_zero(&mut ipad);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + 48);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    let result = sha384(&outer);

    constant_time::secure_zero(&mut opad);

    result
}

pub fn hmac_sha384_verify(key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    let expect = hmac_sha384(key, message);
    constant_time::ct_eq(&expect, mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha384_rfc4231_tc1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 48] = [
            0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46,
            0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c,
            0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1,
            0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
        ];
        let result = hmac_sha384(&key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha384_rfc4231_tc2() {
        // RFC 4231 Test Case 2 — "Jefe" / "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 48] = [
            0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a,
            0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47, 0xe4, 0x2e, 0xc3, 0x73,
            0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32,
            0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49,
        ];
        let result = hmac_sha384(key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha384_verify() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha384(key, data);
        assert!(hmac_sha384_verify(key, data, &mac));
        let mut bad_mac = mac;
        bad_mac[0] ^= 1;
        assert!(!hmac_sha384_verify(key, data, &bad_mac));
    }
}
