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

use super::handlers;
use crate::protocol::{
    encode_response, Request, EINVAL, OP_BLAKE3_HASH, OP_HEALTHCHECK, OP_SHA3_256_HASH,
};

pub fn dispatch(req: Request<'_>) -> Vec<u8> {
    match req.op {
        OP_BLAKE3_HASH => handlers::blake3_hash(req),
        OP_SHA3_256_HASH => handlers::sha3_256_hash(req),
        OP_HEALTHCHECK => handlers::healthcheck(req),
        _ => encode_response(req.op, req.flags, req.request_id, EINVAL, &[]),
    }
}
