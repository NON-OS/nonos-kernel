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

use super::{frame, status};
use crate::security::crypto_capsule::capability::gate_hash;
use crate::security::crypto_capsule::client::{seq::next_request_id, transport::round_trip};
use crate::security::crypto_capsule::error::CryptoCapsuleError;
use crate::security::crypto_capsule::protocol::{
    encode_request, AEAD_TAG_BYTES, MAX_AEAD_AAD_BYTES, MAX_AEAD_PT_BYTES,
};

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
    let request_id = next_request_id();
    let request = encode_request(op, 0, request_id, &frame::build(key, nonce, aad, plaintext));
    let resp = round_trip(request_id, request)?;
    if resp.status != 0 {
        return Err(status::map(resp.status));
    }
    if resp.body.len() != plaintext.len() + AEAD_TAG_BYTES as usize {
        return Err(CryptoCapsuleError::ProtocolMismatch);
    }
    Ok(resp.body)
}
