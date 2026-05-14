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

//! IPv4 egress path. Composes the IPv4 header over the caller's
//! payload, asks `net.l2` to resolve the next-hop MAC, wraps the
//! result in an ethernet frame and ships it down for TX. The
//! next-hop comes from the routing table: on-link destinations
//! use the destination IP itself; off-link ones use the gateway.

use alloc::vec;
use alloc::vec::Vec;

use crate::ipv4::{build as ipv4_build, BuildRequest as Ipv4Build, Ipv4Addr};
use crate::l2_client::{arp_resolve, send_frame, ArpError, TxError};
use crate::route::ROUTES;
use crate::state::IFACE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressError {
    NoConfig,
    NoRoute,
    NoNeighbour,
    L2Failed,
    Build,
}

pub fn send(dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Result<(), EgressError> {
    let src = *IFACE.ipv4.lock();
    if src == [0; 4] {
        return Err(EgressError::NoConfig);
    }
    let next_hop = match ROUTES.lookup(&dst) {
        Some(r) => r.gateway.unwrap_or(dst),
        None => return Err(EgressError::NoRoute),
    };
    let l2_port = IFACE.l2_service_port.load(core::sync::atomic::Ordering::Acquire);
    if l2_port == 0 {
        return Err(EgressError::NoConfig);
    }
    let dst_mac = match arp_resolve(l2_port, next_hop) {
        Ok(m) => m,
        Err(ArpError::NoNeighbour) => return Err(EgressError::NoNeighbour),
        Err(_) => return Err(EgressError::L2Failed),
    };
    let frame = build_frame(src, dst, protocol, payload, dst_mac)?;
    send_frame(l2_port, &frame).map_err(|_: TxError| EgressError::L2Failed)
}

fn build_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, EgressError> {
    let src_mac = *IFACE.mac.lock();
    let id = IFACE.next_id();
    let total = 14 + 20 + payload.len();
    let mut out = vec![0u8; total];
    out[0..6].copy_from_slice(&dst_mac);
    out[6..12].copy_from_slice(&src_mac);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip_built = ipv4_build(
        &Ipv4Build { src, dst, protocol, identification: id, ttl: 0, payload },
        &mut out[14..],
    )
    .map_err(|_| EgressError::Build)?;
    if ip_built + 14 != total {
        return Err(EgressError::Build);
    }
    Ok(out)
}
