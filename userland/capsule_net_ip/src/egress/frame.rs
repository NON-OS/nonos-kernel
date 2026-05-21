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

use super::error::EgressError;
use crate::ipv4::{build as ipv4_build, BuildRequest as Ipv4Build, Ipv4Addr};
use crate::state::IFACE;

pub(super) fn build_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, EgressError> {
    let src_mac = *IFACE.mac.lock();
    let total = 14 + 20 + payload.len();
    let mut out = vec![0u8; total];
    out[0..6].copy_from_slice(&dst_mac);
    out[6..12].copy_from_slice(&src_mac);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let built = ipv4_build(&request(src, dst, protocol, payload), &mut out[14..])
        .map_err(|_| EgressError::Build)?;
    if built + 14 != total {
        return Err(EgressError::Build);
    }
    Ok(out)
}

fn request<'a>(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &'a [u8]) -> Ipv4Build<'a> {
    Ipv4Build { src, dst, protocol, identification: IFACE.next_id(), ttl: 0, payload }
}
