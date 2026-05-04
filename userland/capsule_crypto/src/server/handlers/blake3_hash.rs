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

use crate::protocol::{encode_response, Request, EMSGSIZE, MAX_INPUT_BYTES, OP_BLAKE3_HASH};

// Payload: raw bytes to hash. Bounded by MAX_INPUT_BYTES (already
// enforced by the protocol decoder). Output: 32-byte BLAKE3 digest.
pub fn blake3_hash(req: Request<'_>) -> Vec<u8> {
    if req.payload.len() > MAX_INPUT_BYTES as usize {
        return encode_response(OP_BLAKE3_HASH, req.flags, req.request_id, EMSGSIZE, &[]);
    }
    let digest = blake3::hash(req.payload);
    encode_response(OP_BLAKE3_HASH, req.flags, req.request_id, 0, digest.as_bytes())
}
