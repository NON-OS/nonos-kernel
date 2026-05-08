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

//! Kernel-side client for the crypto capsule's Ed25519 verify op.
//! The capsule does the math; the kernel client only marshals the
//! request, runs the round trip, and maps the status.

extern crate alloc;

use alloc::vec::Vec;

use super::super::capability::gate_hash;
use super::super::error::CryptoCapsuleError;
use super::super::protocol::{
    encode_request, ED25519_HEADER_BYTES, ED25519_PUBKEY_BYTES, ED25519_SIG_BYTES,
    MAX_VERIFY_MESSAGE_BYTES, OP_ED25519_VERIFY,
};
use super::seq::next_request_id;
use super::transport::round_trip;

const PUBKEY_LEN: usize = ED25519_PUBKEY_BYTES as usize;
const SIG_LEN: usize = ED25519_SIG_BYTES as usize;
const HEADER_LEN: usize = ED25519_HEADER_BYTES as usize;

/// Verify `signature` against `message` using `pubkey`. Returns
/// `Ok(())` on a signature that checks. `CryptoCapsuleError::AuthFailure`
/// surfaces a signature that did not check; `InvalidArgument` and
/// `OversizedRequest` are bookkeeping refusals; everything else
/// flows through from the transport.
pub fn verify_ed25519(
    pubkey: &[u8; PUBKEY_LEN],
    signature: &[u8; SIG_LEN],
    message: &[u8],
) -> Result<(), CryptoCapsuleError> {
    let _caller = gate_hash()?;
    if message.len() as u32 > MAX_VERIFY_MESSAGE_BYTES {
        return Err(CryptoCapsuleError::OversizedRequest);
    }

    let mut body: Vec<u8> = Vec::with_capacity(HEADER_LEN + message.len());
    body.extend_from_slice(pubkey);
    body.extend_from_slice(signature);
    body.extend_from_slice(message);

    let request_id = next_request_id();
    let frame = encode_request(OP_ED25519_VERIFY, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;

    if !resp.body.is_empty() {
        return Err(CryptoCapsuleError::ProtocolMismatch);
    }
    match resp.status {
        0 => Ok(()),
        -22 => Err(CryptoCapsuleError::InvalidArgument),
        -90 => Err(CryptoCapsuleError::OversizedRequest),
        -74 => Err(CryptoCapsuleError::AuthFailure),
        -13 => Err(CryptoCapsuleError::AccessDenied),
        _ => Err(CryptoCapsuleError::TransportFailure),
    }
}
