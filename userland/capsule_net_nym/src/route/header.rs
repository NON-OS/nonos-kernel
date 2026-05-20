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

use alloc::vec::Vec;

use super::seed;
use crate::crypto::{blake3, Key};
use crate::packet::{PacketError, HEADER_LEN, OFF_HEADER_RANDOM};
use crate::topology;

pub const ROUTE_HEADER_LEN: usize = HEADER_LEN - OFF_HEADER_RANDOM;

pub fn build(
    id: u32,
    flags: u8,
    key: &Key,
    cred: &[u8; 32],
) -> Result<[u8; ROUTE_HEADER_LEN], PacketError> {
    let seed = seed::route_seed(id, flags, key, cred)?;
    let hops = topology::route(&seed).map_err(|_| PacketError::NoRoute)?;
    let mut out = [0u8; ROUTE_HEADER_LEN];
    for (idx, hop) in hops.iter().enumerate() {
        write_hop(&mut out[idx * 61..idx * 61 + 61], idx as u8, hop, &seed)?;
    }
    Ok(out)
}

fn write_hop(
    out: &mut [u8],
    idx: u8,
    hop: &topology::Node,
    seed: &[u8; 32],
) -> Result<(), PacketError> {
    let mut material = Vec::with_capacity(75);
    material.extend_from_slice(seed);
    material.extend_from_slice(&hop.identity);
    material.extend_from_slice(&hop.packet_key);
    material.push(idx);
    material.extend_from_slice(&hop.delay_ms.to_le_bytes());
    let mut digest = [0u8; 32];
    blake3(&material, &mut digest).map_err(|_| PacketError::Crypto)?;
    out[0..32].copy_from_slice(&digest);
    out[32..64.min(out.len())].copy_from_slice(&hop.identity[..out.len().saturating_sub(32)]);
    Ok(())
}
