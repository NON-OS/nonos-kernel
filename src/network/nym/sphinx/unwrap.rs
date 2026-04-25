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

extern crate alloc;

use super::packet::SphinxPacket;
use crate::network::nym::crypto::keys::blind_public_key;
use crate::network::nym::crypto::{derive_sphinx_keys, x25519_scalar_mult};
use crate::network::nym::error::NymError;
use crate::network::nym::types::MixNodeId;
use alloc::vec::Vec;

pub enum UnwrapResult {
    Forward { next_hop: MixNodeId, packet: SphinxPacket },
    Destination { payload: Vec<u8> },
}

pub fn unwrap_packet(
    packet: &mut SphinxPacket,
    private_key: &[u8; 32],
) -> Result<UnwrapResult, NymError> {
    let shared_secret = x25519_scalar_mult(private_key, &packet.header.alpha);
    let keys = derive_sphinx_keys(&shared_secret);
    let expected_mac = compute_mac(&keys.mac_key, &packet.header.beta);
    if !constant_time_eq(&expected_mac, &packet.header.gamma) {
        return Err(NymError::InvalidMac);
    }
    super::payload::decrypt_payload(&mut packet.payload, &keys.payload_key)?;
    if packet.header.beta.len() < 34 {
        let plaintext = super::payload::unpad_payload(&packet.payload.data).to_vec();
        return Ok(UnwrapResult::Destination { payload: plaintext });
    }
    let mut next_id = [0u8; 32];
    next_id.copy_from_slice(&packet.header.beta[..32]);
    packet.header.beta = packet.header.beta[34..].to_vec();
    packet.header.beta.resize(packet.header.beta.len() + 34, 0);
    packet.header.alpha = blind_public_key(&packet.header.alpha, &keys.blinding_factor);
    let next_hop = MixNodeId(next_id);
    Ok(UnwrapResult::Forward { next_hop, packet: packet.clone() })
}

fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let h = crate::crypto::hash::blake3_keyed_hash(key, data);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&h[..16]);
    mac
}

fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    crate::crypto::util::constant_time::ct_eq(a, b)
}
