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

use nonos_libc::mk_ipc_call;

use super::header::{parse_response, write_request};
use super::seq;
use super::wire::{NIC_HDR_LEN, OP_TX_PACKET};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    SendFailed,
    BadResponse,
    Refused,
}

// Send one ethernet frame to the NIC capsule for TX. The payload
// is the raw frame (including ethernet header); the NIC handler
// prepends its own virtio_net header as needed.
pub fn send_frame(nic_port: u32, frame: &[u8]) -> Result<(), TxError> {
    let total = NIC_HDR_LEN + frame.len();
    let mut req = vec![0u8; total];
    let rid = seq::next();
    write_request(&mut req, OP_TX_PACKET, rid, frame.len() as u32);
    req[NIC_HDR_LEN..total].copy_from_slice(frame);
    let mut resp = [0u8; NIC_HDR_LEN + 4];
    let n = mk_ipc_call(nic_port as u64, req.as_ptr(), total, resp.as_mut_ptr(), resp.len());
    if n < 0 {
        return Err(TxError::SendFailed);
    }
    let (op, _, plen) = parse_response(&resp).ok_or(TxError::BadResponse)?;
    if op != OP_TX_PACKET || plen as usize != 4 {
        return Err(TxError::BadResponse);
    }
    let status = i32::from_le_bytes(resp[NIC_HDR_LEN..NIC_HDR_LEN + 4].try_into().unwrap());
    if status < 0 {
        Err(TxError::Refused)
    } else {
        Ok(())
    }
}
