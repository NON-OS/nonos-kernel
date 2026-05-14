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

//! IPv4 ingress path. The L2 capsule hands us complete ethernet
//! frames; we strip the L2 header, validate the IPv4 header, and
//! surface (src, protocol, payload) for the OP_POLL_PACKET handler
//! to return to the caller. Non-IPv4 frames are silently dropped
//! — ARP is handled inside L2 and never reaches us.

use alloc::vec::Vec;

use crate::ipv4::{parse as ipv4_parse, Ipv4Addr};
use crate::state::IFACE;

#[derive(Clone, Debug)]
pub struct Inbound {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressError {
    NotIpv4,
    BadFrame,
    BadIp,
    NotForUs,
}

pub fn from_frame(frame: &[u8]) -> Result<Inbound, IngressError> {
    if frame.len() < 14 {
        return Err(IngressError::BadFrame);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err(IngressError::NotIpv4);
    }
    let (hdr, payload) =
        ipv4_parse(&frame[14..]).map_err(|_| IngressError::BadIp)?;
    let local = *IFACE.ipv4.lock();
    let broadcast = hdr.dst == [255, 255, 255, 255];
    if local != [0; 4] && hdr.dst != local && !broadcast {
        return Err(IngressError::NotForUs);
    }
    Ok(Inbound { src: hdr.src, dst: hdr.dst, protocol: hdr.protocol, payload: payload.to_vec() })
}
