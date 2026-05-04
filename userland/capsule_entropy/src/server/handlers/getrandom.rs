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

use alloc::vec;
use alloc::vec::Vec;

use crate::pool::Pool;
use crate::protocol::{
    encode_response, Request, EINVAL, EIO, EMSGSIZE, MAX_RANDOM_BYTES, OP_GET_RANDOM,
};

// Payload layout: u32 length (LE). The capsule fills `length` random
// bytes into the response body (after the i32 status word).
pub fn get_random(pool: &Pool, req: Request<'_>) -> Vec<u8> {
    if req.payload.len() < 4 {
        return encode_response(OP_GET_RANDOM, req.flags, req.request_id, EINVAL, &[]);
    }
    let length = u32::from_le_bytes([req.payload[0], req.payload[1], req.payload[2], req.payload[3]]);
    if length > MAX_RANDOM_BYTES {
        return encode_response(OP_GET_RANDOM, req.flags, req.request_id, EMSGSIZE, &[]);
    }
    let length = length as usize;
    let mut out = vec![0u8; length];
    let n = pool.fill(&mut out);
    if n < 0 || (n as usize) != length {
        return encode_response(OP_GET_RANDOM, req.flags, req.request_id, EIO, &[]);
    }
    encode_response(OP_GET_RANDOM, req.flags, req.request_id, 0, &out)
}
