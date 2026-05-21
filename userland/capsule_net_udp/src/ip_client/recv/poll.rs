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

use super::types::{RecvError, UdpInbound, MAX_PACKET};
use crate::ip_client::header::{parse_response, write_request};
use crate::ip_client::seq;
use crate::ip_client::wire::{IP_HDR_LEN, IP_PROTO_UDP, OP_POLL_PACKET};

const BODY_OVERHEAD: usize = 4 + 4 + 1;

pub fn poll_segment(ip_port: u32) -> Result<UdpInbound, RecvError> {
    let mut req = [0u8; IP_HDR_LEN + 1];
    let rid = seq::next();
    write_request(&mut req, OP_POLL_PACKET, rid, 1);
    req[IP_HDR_LEN] = IP_PROTO_UDP;
    let mut resp = vec![0u8; IP_HDR_LEN + BODY_OVERHEAD + MAX_PACKET];
    let n = mk_ipc_call(ip_port as u64, req.as_ptr(), req.len(), resp.as_mut_ptr(), resp.len());
    if n < 0 {
        return Err(RecvError::SendFailed);
    }
    let (op, errno, _, plen) = parse_response(&resp).ok_or(RecvError::BadResponse)?;
    if op != OP_POLL_PACKET {
        return Err(RecvError::BadResponse);
    }
    parse_errno(errno)?;
    let want = IP_HDR_LEN + plen as usize;
    if plen < BODY_OVERHEAD as u32 || want > resp.len() {
        return Err(RecvError::BadResponse);
    }
    parse_body(&resp[..want])
}

fn parse_errno(errno: u16) -> Result<(), RecvError> {
    match errno {
        0 => Ok(()),
        8 => Err(RecvError::NoConfig),
        10 => Err(RecvError::Empty),
        n => Err(RecvError::Other(n)),
    }
}

fn parse_body(resp: &[u8]) -> Result<UdpInbound, RecvError> {
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&resp[IP_HDR_LEN..IP_HDR_LEN + 4]);
    dst.copy_from_slice(&resp[IP_HDR_LEN + 4..IP_HDR_LEN + 8]);
    if resp[IP_HDR_LEN + 8] != IP_PROTO_UDP {
        return Err(RecvError::NotUdp);
    }
    Ok(UdpInbound { src, dst, segment: resp[IP_HDR_LEN + BODY_OVERHEAD..].to_vec() })
}
