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

use super::hmac_core::hmac_sha256 as mac;
use crate::protocol::{encode_response, Request, EINVAL, EMSGSIZE, HMAC_KEY_MAX, OP_HMAC_SHA256};

pub fn hmac_sha256(req: Request<'_>) -> Vec<u8> {
    if req.payload.len() < 4 {
        return encode_response(OP_HMAC_SHA256, req.flags, req.request_id, EINVAL, &[]);
    }
    let key_len = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]) as usize;
    if key_len > HMAC_KEY_MAX || req.payload.len() < 4 + key_len {
        return encode_response(OP_HMAC_SHA256, req.flags, req.request_id, EMSGSIZE, &[]);
    }
    let key = &req.payload[4..4 + key_len];
    let msg = &req.payload[4 + key_len..];
    let out = mac(key, msg);
    encode_response(OP_HMAC_SHA256, req.flags, req.request_id, 0, &out)
}
