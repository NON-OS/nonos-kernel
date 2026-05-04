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

use alloc::string::String;
use alloc::vec::Vec;

use super::super::capability::gate_caller;
use super::super::error::VfsCapsuleError;
use super::super::protocol::{encode_request, MAX_PATH_BYTES, OP_LIST};
use super::errno::map_status;
use super::seq::next_request_id;
use super::transport::round_trip;

pub fn list(prefix: &str) -> Result<Vec<String>, VfsCapsuleError> {
    let pid = gate_caller()?;
    let pb = prefix.as_bytes();
    if pb.len() > MAX_PATH_BYTES as usize {
        return Err(VfsCapsuleError::InvalidArgument);
    }
    let mut body = Vec::with_capacity(5 + pb.len());
    body.extend_from_slice(&pid.to_le_bytes());
    body.push(pb.len() as u8);
    body.extend_from_slice(pb);

    let request_id = next_request_id();
    let frame = encode_request(OP_LIST, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < resp.body.len() {
        let n = resp.body[i] as usize;
        i += 1;
        if i + n > resp.body.len() {
            return Err(VfsCapsuleError::ProtocolMismatch);
        }
        let s = match core::str::from_utf8(&resp.body[i..i + n]) {
            Ok(s) => String::from(s),
            Err(_) => return Err(VfsCapsuleError::ProtocolMismatch),
        };
        out.push(s);
        i += n;
    }
    Ok(out)
}
