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

use core::sync::atomic::Ordering;

use super::error::EgressError;
use super::frame::build_frame;
use crate::ipv4::Ipv4Addr;
use crate::l2_client::{arp_resolve, send_frame, ArpError, TxError};
use crate::route::ROUTES;
use crate::state::IFACE;

pub fn send(dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Result<(), EgressError> {
    let src = configured_ip()?;
    let l2_port = configured_l2_port()?;
    let dst_mac = resolve_mac(l2_port, next_hop(dst)?)?;
    let frame = build_frame(src, dst, protocol, payload, dst_mac)?;
    send_frame(l2_port, &frame).map_err(|_: TxError| EgressError::L2Failed)
}

fn configured_ip() -> Result<Ipv4Addr, EgressError> {
    let src = *IFACE.ipv4.lock();
    if src == [0; 4] {
        return Err(EgressError::NoConfig);
    }
    Ok(src)
}

fn configured_l2_port() -> Result<u32, EgressError> {
    match IFACE.l2_service_port.load(Ordering::Acquire) {
        0 => Err(EgressError::NoConfig),
        port => Ok(port),
    }
}

fn next_hop(dst: Ipv4Addr) -> Result<Ipv4Addr, EgressError> {
    ROUTES
        .lookup(&dst)
        .map(|r| r.gateway.map_or(dst, |gateway| gateway))
        .ok_or(EgressError::NoRoute)
}

fn resolve_mac(l2_port: u32, next_hop: Ipv4Addr) -> Result<[u8; 6], EgressError> {
    match arp_resolve(l2_port, next_hop) {
        Ok(mac) => Ok(mac),
        Err(ArpError::NoNeighbour) => Err(EgressError::NoNeighbour),
        Err(_) => Err(EgressError::L2Failed),
    }
}
