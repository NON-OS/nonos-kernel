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

use alloc::vec;
use alloc::vec::Vec;

use super::poly;
use super::types::{NtruCiphertext, NtruPublicKey, NtruSecretKey};
use super::{NTRU_CIPHERTEXT_BYTES, NTRU_LOG_Q, NTRU_N, NTRU_PUBLICKEY_BYTES, NTRU_Q, NTRU_SECRETKEY_BYTES};

pub fn ntru_serialize_public_key(pk: &NtruPublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(NTRU_PUBLICKEY_BYTES);

    let mut bits = 0u32;
    let mut num_bits = 0;

    for &coeff in &pk.h {
        let val = ((coeff as i32 + (NTRU_Q as i32 / 2)) as u16) % NTRU_Q;
        bits |= (val as u32) << num_bits;
        num_bits += NTRU_LOG_Q;

        while num_bits >= 8 {
            out.push((bits & 0xFF) as u8);
            bits >>= 8;
            num_bits -= 8;
        }
    }

    if num_bits > 0 {
        out.push((bits & 0xFF) as u8);
    }

    out
}

pub fn ntru_deserialize_public_key(bytes: &[u8]) -> Result<NtruPublicKey, &'static str> {
    if bytes.len() < NTRU_PUBLICKEY_BYTES {
        return Err("Invalid public key length");
    }

    let mut h = vec![0i16; NTRU_N];
    let mut bits = 0u32;
    let mut num_bits = 0;
    let mut byte_idx = 0;
    let mask = (1u32 << NTRU_LOG_Q) - 1;

    for coeff in &mut h {
        while num_bits < NTRU_LOG_Q && byte_idx < bytes.len() {
            bits |= (bytes[byte_idx] as u32) << num_bits;
            num_bits += 8;
            byte_idx += 1;
        }

        let val = (bits & mask) as i16;
        bits >>= NTRU_LOG_Q;
        num_bits -= NTRU_LOG_Q;

        *coeff = val - (NTRU_Q as i16 / 2);
    }

    Ok(NtruPublicKey { h })
}

pub fn ntru_serialize_secret_key(sk: &NtruSecretKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(NTRU_SECRETKEY_BYTES);

    for chunk in sk.f.chunks(4) {
        let mut byte = 0u8;
        for (i, &c) in chunk.iter().enumerate() {
            let val = ((c + 1) & 0x03) as u8;
            byte |= val << (i * 2);
        }
        out.push(byte);
    }

    out.extend(ntru_serialize_public_key(&sk.pk));

    out
}

pub fn ntru_deserialize_secret_key(bytes: &[u8]) -> Result<NtruSecretKey, &'static str> {
    let f_packed_len = (NTRU_N + 3) / 4;
    if bytes.len() < f_packed_len + NTRU_PUBLICKEY_BYTES {
        return Err("Invalid secret key length");
    }

    let mut f = vec![0i16; NTRU_N];
    for (i, &byte) in bytes[..f_packed_len].iter().enumerate() {
        for j in 0..4 {
            let idx = i * 4 + j;
            if idx < NTRU_N {
                let val = ((byte >> (j * 2)) & 0x03) as i16;
                f[idx] = val - 1;
            }
        }
    }

    let pk = ntru_deserialize_public_key(&bytes[f_packed_len..])?;

    let f_poly = poly::Polynomial::from_coeffs(f.clone());
    let fp = poly::poly_inverse_mod_3(&f_poly).ok_or("Cannot compute f inverse")?;

    Ok(NtruSecretKey { f, fp: fp.coeffs, pk })
}

pub fn ntru_serialize_ciphertext(ct: &NtruCiphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(NTRU_CIPHERTEXT_BYTES);

    let mut bits = 0u32;
    let mut num_bits = 0;

    for &coeff in &ct.c {
        let val = ((coeff as i32 + (NTRU_Q as i32 / 2)) as u16) % NTRU_Q;
        bits |= (val as u32) << num_bits;
        num_bits += NTRU_LOG_Q;

        while num_bits >= 8 {
            out.push((bits & 0xFF) as u8);
            bits >>= 8;
            num_bits -= 8;
        }
    }

    if num_bits > 0 {
        out.push((bits & 0xFF) as u8);
    }

    out
}

pub fn ntru_deserialize_ciphertext(bytes: &[u8]) -> Result<NtruCiphertext, &'static str> {
    if bytes.len() < NTRU_CIPHERTEXT_BYTES {
        return Err("Invalid ciphertext length");
    }

    let mut c = vec![0i16; NTRU_N];
    let mut bits = 0u32;
    let mut num_bits = 0;
    let mut byte_idx = 0;
    let mask = (1u32 << NTRU_LOG_Q) - 1;

    for coeff in &mut c {
        while num_bits < NTRU_LOG_Q && byte_idx < bytes.len() {
            bits |= (bytes[byte_idx] as u32) << num_bits;
            num_bits += 8;
            byte_idx += 1;
        }

        let val = (bits & mask) as i16;
        bits >>= NTRU_LOG_Q;
        num_bits -= NTRU_LOG_Q;

        *coeff = val - (NTRU_Q as i16 / 2);
    }

    Ok(NtruCiphertext { c })
}
