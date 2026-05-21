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

//! `round_trip` is the one entry capsules use to talk to another
//! capsule. The caller hands a request payload, a target service
//! port, and the magic/version pair that identifies its protocol;
//! the helper writes the v2 envelope, sends it, blocks on the
//! reply inbox, and copies the response payload back. The
//! response envelope shape mirrors v2 with `reply_port == 0` so
//! a v1 listener can still decode the first 20 bytes when it
//! upgrades.

use super::envelope::{write_request_v2, RequestV2, HDR_LEN_V2, VERSION_V2};
use super::error::TransportError;
use super::seq::Counter;
use super::wire::{le_u16, le_u32};
use crate::ipc::{mk_ipc_recv, mk_ipc_send};

const RECV_OWN_INBOX: u64 = 0;

pub struct RoundTrip<'a> {
    pub target_port: u64,
    pub reply_port: u32,
    pub magic: u32,
    pub op: u16,
    pub flags: u16,
    pub payload: &'a [u8],
    pub timeout_ms: u64,
}

pub struct Response<'a> {
    pub op: u16,
    pub errno: u16,
    pub request_id: u32,
    pub payload: &'a [u8],
}

pub fn round_trip<'a, 'b>(
    counter: &Counter,
    req: RoundTrip<'a>,
    out_buf: &'b mut [u8],
    scratch: &mut [u8],
) -> Result<Response<'b>, TransportError> {
    let request_id = counter.fetch();
    let payload_len = req.payload.len() as u32;
    let total = HDR_LEN_V2 + req.payload.len();
    if scratch.len() < total {
        return Err(TransportError::ResponseTooLarge);
    }
    write_request_v2(
        &mut scratch[..HDR_LEN_V2],
        &RequestV2 {
            magic: req.magic,
            op: req.op,
            flags: req.flags,
            reply_port: req.reply_port,
            request_id,
            payload_len,
        },
    );
    scratch[HDR_LEN_V2..total].copy_from_slice(req.payload);

    let sent = mk_ipc_send(req.target_port, scratch.as_ptr(), total);
    if sent < 0 {
        return Err(TransportError::SendFailed);
    }

    let n = mk_ipc_recv(RECV_OWN_INBOX, out_buf.as_mut_ptr(), out_buf.len(), req.timeout_ms);
    if n < 0 {
        return Err(TransportError::RecvTimeout);
    }
    let n = n as usize;
    if n < HDR_LEN_V2 {
        return Err(TransportError::ResponseTooShort);
    }
    let resp_magic = le_u32(out_buf, 0).ok_or(TransportError::ResponseTooShort)?;
    if resp_magic != req.magic {
        return Err(TransportError::MagicMismatch);
    }
    let version = le_u16(out_buf, 4).ok_or(TransportError::ResponseTooShort)?;
    if version != VERSION_V2 {
        return Err(TransportError::VersionMismatch);
    }
    let op = le_u16(out_buf, 6).ok_or(TransportError::ResponseTooShort)?;
    let errno = le_u16(out_buf, 8).ok_or(TransportError::ResponseTooShort)?;
    let rid = le_u32(out_buf, 16).ok_or(TransportError::ResponseTooShort)?;
    let plen = le_u32(out_buf, 20).ok_or(TransportError::ResponseTooShort)? as usize;
    if rid != request_id {
        return Err(TransportError::RequestIdMismatch);
    }
    let payload_end = HDR_LEN_V2.checked_add(plen).ok_or(TransportError::ResponseTooLarge)?;
    if payload_end > n {
        return Err(TransportError::ResponseTooShort);
    }
    Ok(Response { op, errno, request_id: rid, payload: &out_buf[HDR_LEN_V2..payload_end] })
}
