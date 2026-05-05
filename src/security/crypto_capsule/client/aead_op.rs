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

//! Shared body for the four AEAD ops the crypto capsule serves
//! (AES-256-GCM seal/open, ChaCha20-Poly1305 seal/open). Each pair
//! differs only by its protocol opcode; the wire frame layout, size
//! checks, and errno mapping are identical. Cap-gated by `CAP_CRYPTO`.

use alloc::vec::Vec;

use super::super::capability::gate_hash;
use super::super::error::CryptoCapsuleError;
use super::super::protocol::{
    encode_request, AEAD_HEADER_BYTES, AEAD_TAG_BYTES, MAX_AEAD_AAD_BYTES, MAX_AEAD_PT_BYTES,
};
use super::seq::next_request_id;
use super::transport::round_trip;

pub(super) fn seal(
    op: u16,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoCapsuleError> {
    let _caller = gate_hash()?;
    if aad.len() > MAX_AEAD_AAD_BYTES as usize || plaintext.len() > MAX_AEAD_PT_BYTES as usize {
        return Err(CryptoCapsuleError::OversizedRequest);
    }
    let frame = build_frame(key, nonce, aad, plaintext);
    let request_id = next_request_id();
    let request = encode_request(op, 0, request_id, &frame);
    let resp = round_trip(request_id, request)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() != plaintext.len() + AEAD_TAG_BYTES as usize {
        return Err(CryptoCapsuleError::ProtocolMismatch);
    }
    Ok(resp.body)
}

pub(super) fn open(
    op: u16,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoCapsuleError> {
    let _caller = gate_hash()?;
    if aad.len() > MAX_AEAD_AAD_BYTES as usize {
        return Err(CryptoCapsuleError::OversizedRequest);
    }
    if ciphertext.len() < AEAD_TAG_BYTES as usize
        || ciphertext.len() > MAX_AEAD_PT_BYTES as usize + AEAD_TAG_BYTES as usize
    {
        return Err(CryptoCapsuleError::OversizedRequest);
    }
    let frame = build_frame(key, nonce, aad, ciphertext);
    let request_id = next_request_id();
    let request = encode_request(op, 0, request_id, &frame);
    let resp = round_trip(request_id, request)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() + AEAD_TAG_BYTES as usize != ciphertext.len() {
        return Err(CryptoCapsuleError::ProtocolMismatch);
    }
    Ok(resp.body)
}

fn build_frame(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(AEAD_HEADER_BYTES as usize + aad.len() + payload.len());
    frame.extend_from_slice(key);
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&(aad.len() as u32).to_le_bytes());
    frame.extend_from_slice(aad);
    frame.extend_from_slice(payload);
    frame
}

fn map_status(status: i32) -> CryptoCapsuleError {
    match status {
        -22 => CryptoCapsuleError::InvalidArgument,
        -74 => CryptoCapsuleError::AuthFailure,
        -90 => CryptoCapsuleError::OversizedRequest,
        -13 => CryptoCapsuleError::AccessDenied,
        _ => CryptoCapsuleError::TransportFailure,
    }
}
