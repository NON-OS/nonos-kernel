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

//! Encode/decode helpers built on the shared lifecycle transport.
//! The kernel client speaks the same v1 envelope as every other
//! userland service capsule; the protocol-mismatch path catches a
//! drift between this magic/version and the userland header.

use alloc::vec::Vec;

use super::header::{MAGIC, MAX_PAYLOAD_BYTES, VERSION};
use crate::services::lifecycle::transport::{self, DecodedResponse};

pub(in super::super) fn encode_request(
    op: u16,
    flags: u16,
    request_id: u32,
    body: &[u8],
) -> Vec<u8> {
    transport::encode_request(MAGIC, VERSION, op, flags, request_id, body)
}

pub(in super::super) fn decode_response(buf: &[u8]) -> Option<DecodedResponse<'_>> {
    transport::decode_v1_response(buf, MAGIC, VERSION, MAX_PAYLOAD_BYTES)
}
