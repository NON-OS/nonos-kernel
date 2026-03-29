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

use crate::services::ServiceResponse;

const ERR_INVAL: i32 = -22;
const ERR_CRYPTO: i32 = -100;

pub(super) fn hash_data(seq: u32, data: &[u8]) -> ServiceResponse {
    let hash = crate::crypto::hash::blake3_hash(data);
    ServiceResponse::ok(seq, hash.to_vec())
}

pub(super) fn sign_data(seq: u32, data: &[u8]) -> ServiceResponse {
    let mut sig_buf = [0u8; 64];
    match crate::crypto::sign_message(0, data, &mut sig_buf) {
        Ok(_) => ServiceResponse::ok(seq, sig_buf.to_vec()),
        Err(_) => ServiceResponse::err(seq, ERR_CRYPTO),
    }
}

pub(super) fn verify_sig(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 64 {
        return ServiceResponse::err(seq, ERR_INVAL);
    }
    let sig = &data[..64];
    let msg = &data[64..];
    let valid = crate::crypto::verify_signature_syscall(0, msg, sig).unwrap_or(false);
    ServiceResponse::ok(seq, alloc::vec![valid as u8])
}

pub(super) fn encrypt_data(seq: u32, data: &[u8]) -> ServiceResponse {
    let key = crate::crypto::get_random_bytes();
    let aead = crate::crypto::Chacha20Poly1305Aead::new(&key);
    let mut nonce = [0u8; 12];
    crate::crypto::fill_random_bytes(&mut nonce);
    match crate::crypto::aead_wrap(&aead, &nonce, &[], data) {
        Ok(mut ct) => {
            let mut out = key.to_vec();
            out.append(&mut ct);
            ServiceResponse::ok(seq, out)
        }
        Err(_) => ServiceResponse::err(seq, ERR_CRYPTO),
    }
}

pub(super) fn decrypt_data(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 32 {
        return ServiceResponse::err(seq, ERR_INVAL);
    }
    let key: [u8; 32] = data[..32].try_into().unwrap_or([0u8; 32]);
    let ct = &data[32..];
    let aead = crate::crypto::Chacha20Poly1305Aead::new(&key);
    match crate::crypto::aead_unwrap(&aead, &[], ct) {
        Ok(pt) => ServiceResponse::ok(seq, pt),
        Err(_) => ServiceResponse::err(seq, ERR_CRYPTO),
    }
}

pub(super) fn get_random(seq: u32, data: &[u8]) -> ServiceResponse {
    let len = if data.is_empty() { 32 } else { data[0] as usize };
    let mut buf = alloc::vec![0u8; len];
    crate::crypto::fill_random_bytes(&mut buf);
    ServiceResponse::ok(seq, buf)
}
