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
use super::super::error::WifiError;

pub(crate) fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<(), WifiError> {
    let dk_len = output.len();
    let h_len = 20;

    let mut block_num = 1u32;
    let mut offset = 0;

    while offset < dk_len {
        let mut u = hmac_sha1(password, &[salt, &block_num.to_be_bytes()].concat());
        let mut result = u;

        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for j in 0..h_len {
                result[j] ^= u[j];
            }
        }

        let to_copy = core::cmp::min(h_len, dk_len - offset);
        output[offset..offset + to_copy].copy_from_slice(&result[..to_copy]);
        offset += to_copy;
        block_num += 1;
    }

    Ok(())
}

pub(crate) fn prf_sha1(key: &[u8], label: &[u8], data: &[u8], output: &mut [u8]) -> Result<(), WifiError> {
    let mut offset = 0;
    let mut counter = 0u8;

    while offset < output.len() {
        let mut input = Vec::with_capacity(label.len() + data.len() + 2);
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(data);
        input.push(counter);

        let hash = hmac_sha1(key, &input);
        let to_copy = core::cmp::min(20, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);
        offset += to_copy;
        counter += 1;
    }

    Ok(())
}

pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 20;

    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = sha1(key);
        k[..HASH_SIZE].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

#[allow(deprecated)]  // Required for WPA2 protocol compatibility
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let hash = crate::crypto::hash::sha1(data);
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash[..20]);
    result
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    crate::crypto::hmac_sha256(key, data)
}

pub fn compute_mic_aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; 16], WifiError> {
    if key.len() != 16 {
        return Err(WifiError::InvalidKey);
    }

    let mut k1 = [0u8; 16];
    let mut k2 = [0u8; 16];

    let l = aes_ecb_encrypt(key, &[0u8; 16])?;
    generate_cmac_subkeys(&l, &mut k1, &mut k2);

    let n = (data.len() + 15) / 16;
    let complete = data.len() % 16 == 0 && !data.is_empty();

    let mut x = [0u8; 16];
    let mut y;

    for i in 0..n {
        let start = i * 16;
        let end = core::cmp::min(start + 16, data.len());
        let block = &data[start..end];

        if i == n - 1 {
            let mut m = [0u8; 16];
            m[..block.len()].copy_from_slice(block);

            if complete {
                for j in 0..16 {
                    m[j] ^= k1[j];
                }
            } else {
                m[block.len()] = 0x80;
                for j in 0..16 {
                    m[j] ^= k2[j];
                }
            }

            for j in 0..16 {
                y = x[j] ^ m[j];
                x[j] = y;
            }
        } else {
            for j in 0..16 {
                y = x[j] ^ block[j];
                x[j] = y;
            }
        }

        x = aes_ecb_encrypt(key, &x)?;
    }

    Ok(x)
}

fn generate_cmac_subkeys(l: &[u8; 16], k1: &mut [u8; 16], k2: &mut [u8; 16]) {
    const RB: u8 = 0x87;

    let msb = l[0] & 0x80;
    for i in 0..15 {
        k1[i] = (l[i] << 1) | (l[i + 1] >> 7);
    }
    k1[15] = l[15] << 1;
    if msb != 0 {
        k1[15] ^= RB;
    }

    let msb = k1[0] & 0x80;
    for i in 0..15 {
        k2[i] = (k1[i] << 1) | (k1[i + 1] >> 7);
    }
    k2[15] = k1[15] << 1;
    if msb != 0 {
        k2[15] ^= RB;
    }
}

pub(crate) fn aes_ecb_encrypt(key: &[u8], block: &[u8; 16]) -> Result<[u8; 16], WifiError> {
    if key.len() != 16 {
        return Err(WifiError::InvalidKey);
    }
    let key_arr: [u8; 16] = key.try_into().map_err(|_| WifiError::InvalidKey)?;
    let cipher = crate::crypto::aes::Aes128::new(&key_arr);
    Ok(cipher.encrypt_block(block))
}

pub(crate) fn aes_ecb_decrypt(key: &[u8], block: &[u8; 16]) -> Result<[u8; 16], WifiError> {
    if key.len() != 16 {
        return Err(WifiError::InvalidKey);
    }
    let key_arr: [u8; 16] = key.try_into().map_err(|_| WifiError::InvalidKey)?;
    let cipher = crate::crypto::aes::Aes128::new(&key_arr);
    Ok(cipher.decrypt_block(block))
}

pub(crate) fn aes_key_unwrap(kek: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, WifiError> {
    if ciphertext.len() < 24 || ciphertext.len() % 8 != 0 {
        return Err(WifiError::InvalidKey);
    }

    let n = (ciphertext.len() / 8) - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&ciphertext[0..8]);

    let mut r: Vec<[u8; 8]> = Vec::with_capacity(n);
    for i in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&ciphertext[(i + 1) * 8..(i + 2) * 8]);
        r.push(block);
    }

    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = ((n * j) + i + 1) as u64;

            let t_bytes = t.to_be_bytes();
            for k in 0..8 {
                a[k] ^= t_bytes[k];
            }

            let mut block = [0u8; 16];
            block[0..8].copy_from_slice(&a);
            block[8..16].copy_from_slice(&r[i]);

            let decrypted = aes_ecb_decrypt(kek, &block)?;
            a.copy_from_slice(&decrypted[0..8]);
            r[i].copy_from_slice(&decrypted[8..16]);
        }
    }

    const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    if a != DEFAULT_IV {
        return Err(WifiError::IntegrityFailure);
    }

    let mut result = Vec::with_capacity(n * 8);
    for block in r {
        result.extend_from_slice(&block);
    }
    Ok(result)
}

pub(crate) fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8], length: usize) -> [u8; 32] {
    let mut input = Vec::with_capacity(info.len() + 1);
    input.extend_from_slice(info);
    input.push(0x01);

    let mut output = hmac_sha256(prk, &input);

    for i in length..32 {
        output[i] = 0;
    }

    output
}
