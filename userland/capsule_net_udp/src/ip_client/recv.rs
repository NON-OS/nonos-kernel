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

use nonos_libc::mk_ipc_call;

use super::header::{parse_response, write_request};
use super::seq;
use super::wire::{IP_HDR_LEN, IP_PROTO_UDP, OP_POLL_PACKET};

// 4 src + 4 dst + 1 proto + payload. Sized for IPv4 MTU.
pub const MAX_PACKET: usize = 1500;
const BODY_OVERHEAD: usize = 4 + 4 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpInbound {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub segment: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    SendFailed,
    BadResponse,
    Empty,
    NoConfig,
    NotUdp,
    Other(u16),
}

// Poll `net.ip` for one inbound IPv4 packet and filter for UDP.
// Anything else (ICMP, raw IP) we treat as `NotUdp` so the caller
// can decide whether to drop or just keep polling.
pub fn poll_segment(ip_port: u32) -> Result<UdpInbound, RecvError> {
    let mut req = [0u8; IP_HDR_LEN];
    let rid = seq::next();
    write_request(&mut req, OP_POLL_PACKET, rid, 0);
    let mut resp = vec![0u8; IP_HDR_LEN + BODY_OVERHEAD + MAX_PACKET];
    let n = mk_ipc_call(
        ip_port as u64,
        req.as_ptr(),
        IP_HDR_LEN,
        resp.as_mut_ptr(),
        resp.len(),
    );
    if n < 0 {
        return Err(RecvError::SendFailed);
    }
    let (op, errno, _, plen) = parse_response(&resp).ok_or(RecvError::BadResponse)?;
    if op != OP_POLL_PACKET {
        return Err(RecvError::BadResponse);
    }
    if errno == 8 {
        return Err(RecvError::Empty);
    }
    if errno == 4 {
        return Err(RecvError::NoConfig);
    }
    if errno != 0 {
        return Err(RecvError::Other(errno));
    }
    let want = IP_HDR_LEN + plen as usize;
    if plen < BODY_OVERHEAD as u32 || want > resp.len() {
        return Err(RecvError::BadResponse);
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&resp[IP_HDR_LEN..IP_HDR_LEN + 4]);
    dst.copy_from_slice(&resp[IP_HDR_LEN + 4..IP_HDR_LEN + 8]);
    let proto = resp[IP_HDR_LEN + 8];
    if proto != IP_PROTO_UDP {
        return Err(RecvError::NotUdp);
    }
    let seg = resp[IP_HDR_LEN + BODY_OVERHEAD..want].to_vec();
    Ok(UdpInbound { src, dst, segment: seg })
}
