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
use super::goppa::{compute_parity_check_matrix, to_systematic_form};
use super::{
    MCELIECE_N, MCELIECE_T, MCELIECE_PUBLICKEY_BYTES, MCELIECE_SECRETKEY_BYTES, MCELIECE_CIPHERTEXT_BYTES,
    McEliecePublicKey, McElieceSecretKey, McElieceCiphertext,
};

pub fn mceliece_serialize_public_key(pk: &McEliecePublicKey) -> Vec<u8> {
    pk.t_matrix.clone()
}

pub fn mceliece_deserialize_public_key(bytes: &[u8]) -> Result<McEliecePublicKey, &'static str> {
    if bytes.len() < MCELIECE_PUBLICKEY_BYTES / 2 {
        return Err("Invalid public key length");
    }
    Ok(McEliecePublicKey { t_matrix: bytes.to_vec() })
}

pub fn mceliece_serialize_secret_key(sk: &McElieceSecretKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(MCELIECE_SECRETKEY_BYTES);
    for &coeff in &sk.goppa_poly {
        out.extend_from_slice(&coeff.to_le_bytes());
    }

    for &elem in &sk.support {
        out.extend_from_slice(&elem.to_le_bytes());
    }

    for &p in &sk.permutation {
        out.extend_from_slice(&p.to_le_bytes());
    }

    out
}

pub fn mceliece_deserialize_secret_key(bytes: &[u8]) -> Result<McElieceSecretKey, &'static str> {
    if bytes.len() < 2 * (MCELIECE_T + 1) {
        return Err("Invalid secret key length");
    }

    let mut offset = 0;
    let mut goppa_poly = vec![0u16; MCELIECE_T + 1];
    for coeff in &mut goppa_poly {
        if offset + 2 > bytes.len() {
            return Err("Truncated secret key");
        }
        *coeff = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
    }

    let mut support = vec![0u16; MCELIECE_N];
    for elem in &mut support {
        if offset + 2 > bytes.len() {
            break;
        }
        *elem = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
    }

    let mut permutation = vec![0u16; MCELIECE_N];
    for p in &mut permutation {
        if offset + 2 > bytes.len() {
            break;
        }
        *p = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
    }

    let h = compute_parity_check_matrix(&goppa_poly, &support);
    let t_matrix = to_systematic_form(&h).ok_or("Failed to compute systematic form")?;

    Ok(McElieceSecretKey {
        goppa_poly,
        support,
        permutation,
        pk: McEliecePublicKey { t_matrix },
    })
}

pub fn mceliece_serialize_ciphertext(ct: &McElieceCiphertext) -> Vec<u8> {
    ct.c.clone()
}

pub fn mceliece_deserialize_ciphertext(bytes: &[u8]) -> Result<McElieceCiphertext, &'static str> {
    if bytes.len() < MCELIECE_CIPHERTEXT_BYTES {
        return Err("Invalid ciphertext length");
    }
    Ok(McElieceCiphertext { c: bytes.to_vec() })
}
