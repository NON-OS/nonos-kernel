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

use crate::pool::Pool;
use crate::protocol::{encode_response, Request, EINVAL, MAX_RESEED_BYTES, OP_RESEED};

// TODO(M1-3): drive the future userland DRBG mixer once it lands. The
// current pool is a thin `crypto_random` proxy that has no separate
// state to mix into; this handler bounds-checks the payload, records
// a stat, and acks. The cap (`CAP_ENTROPY_ADMIN`) is enforced by the
// kernel-side client before the request reaches the capsule.
pub fn reseed(pool: &Pool, req: Request<'_>) -> Vec<u8> {
    if req.payload.len() < 4 {
        return encode_response(OP_RESEED, req.flags, req.request_id, EINVAL, &[]);
    }
    let length = u32::from_le_bytes([req.payload[0], req.payload[1], req.payload[2], req.payload[3]]);
    if length > MAX_RESEED_BYTES {
        return encode_response(OP_RESEED, req.flags, req.request_id, EINVAL, &[]);
    }
    if 4usize.saturating_add(length as usize) != req.payload.len() {
        return encode_response(OP_RESEED, req.flags, req.request_id, EINVAL, &[]);
    }
    pool.record_reseed();
    encode_response(OP_RESEED, req.flags, req.request_id, 0, &[])
}
