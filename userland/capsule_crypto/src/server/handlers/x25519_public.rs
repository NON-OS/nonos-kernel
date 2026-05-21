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
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::{encode_response, Request, EINVAL, OP_X25519_PUBLIC, X25519_KEY_BYTES};

pub fn x25519_public(req: Request<'_>) -> Vec<u8> {
    if req.payload.len() != X25519_KEY_BYTES {
        return encode_response(OP_X25519_PUBLIC, req.flags, req.request_id, EINVAL, &[]);
    }
    let mut private = [0u8; X25519_KEY_BYTES];
    private.copy_from_slice(req.payload);
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret);
    encode_response(OP_X25519_PUBLIC, req.flags, req.request_id, 0, public.as_bytes())
}
