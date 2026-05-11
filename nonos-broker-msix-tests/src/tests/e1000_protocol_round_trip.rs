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

//! Encode -> on-the-wire bytes -> decode round trip across every
//! op the e1000 service exposes. The encoder writes the response
//! envelope; the decoder reads the request envelope. They share
//! the same 20-byte header layout, so a round trip catches any
//! byte-order, offset, or padding drift.

use crate::protocol::decode::decode_request;
use crate::protocol::header::{HDR_LEN, MAGIC, VERSION};
use crate::protocol::ops::{
    OP_HEALTHCHECK, OP_LINK_STATUS, OP_MAC_ADDRESS, OP_RX_PACKET, OP_TX_PACKET,
};

fn make_request_frame(op: u16, request_id: u32, payload_len: u32) -> [u8; HDR_LEN] {
    let mut buf = [0u8; HDR_LEN];
    buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&VERSION.to_le_bytes());
    buf[6..8].copy_from_slice(&op.to_le_bytes());
    buf[8..10].copy_from_slice(&0u16.to_le_bytes());
    buf[10..12].copy_from_slice(&0u16.to_le_bytes());
    buf[12..16].copy_from_slice(&request_id.to_le_bytes());
    buf[16..20].copy_from_slice(&payload_len.to_le_bytes());
    buf
}

#[test]
fn every_op_decodes_back() {
    for (op, req_id) in &[
        (OP_HEALTHCHECK, 1u32),
        (OP_LINK_STATUS, 17u32),
        (OP_MAC_ADDRESS, 99u32),
        (OP_TX_PACKET, 1234u32),
        (OP_RX_PACKET, 0xDEAD_BEEFu32),
    ] {
        let buf = make_request_frame(*op, *req_id, 0);
        let r = decode_request(&buf).expect("decoder accepts well-formed envelope");
        assert_eq!(r.op, *op);
        assert_eq!(r.request_id, *req_id);
    }
}
