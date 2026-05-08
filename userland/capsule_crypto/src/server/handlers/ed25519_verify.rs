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

//! Ed25519 verify handler. Payload layout: pubkey[32] || sig[64]
//! || message bytes. Returns status only — `0` on success,
//! `EBADMSG` on a signature that does not check, `EINVAL` for a
//! malformed pubkey, and `EMSGSIZE` for an oversize or undersize
//! payload. Crypto lives here in capsule_crypto; capsule_market
//! and any other caller talks to this op through the kernel
//! transport, never via a direct Ed25519 dependency.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::protocol::{
    encode_response, Request, EBADMSG, EINVAL, EMSGSIZE, ED25519_HEADER_BYTES,
    ED25519_PUBKEY_BYTES, ED25519_SIG_BYTES, MAX_VERIFY_MESSAGE_BYTES, OP_ED25519_VERIFY,
};

const PUBKEY_LEN: usize = ED25519_PUBKEY_BYTES as usize;
const SIG_LEN: usize = ED25519_SIG_BYTES as usize;
const HEADER_LEN: usize = ED25519_HEADER_BYTES as usize;

pub fn ed25519_verify(req: Request<'_>) -> Vec<u8> {
    if req.payload.len() < HEADER_LEN {
        return reply(req, EMSGSIZE);
    }
    let message_len = req.payload.len() - HEADER_LEN;
    if message_len as u32 > MAX_VERIFY_MESSAGE_BYTES {
        return reply(req, EMSGSIZE);
    }

    let pubkey_bytes: [u8; PUBKEY_LEN] = match req.payload[..PUBKEY_LEN].try_into() {
        Ok(k) => k,
        Err(_) => return reply(req, EINVAL),
    };
    let sig_bytes: [u8; SIG_LEN] = match req.payload[PUBKEY_LEN..HEADER_LEN].try_into() {
        Ok(s) => s,
        Err(_) => return reply(req, EINVAL),
    };
    let message = &req.payload[HEADER_LEN..];

    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return reply(req, EINVAL),
    };
    let signature = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(message, &signature) {
        Ok(()) => reply(req, 0),
        Err(_) => reply(req, EBADMSG),
    }
}

fn reply(req: Request<'_>, status: i32) -> Vec<u8> {
    encode_response(OP_ED25519_VERIFY, req.flags, req.request_id, status, &[])
}
