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

use crate::network::nym::crypto::keys::blind_public_key;
use crate::network::nym::crypto::{derive_sphinx_keys, x25519_base_point_mult, x25519_scalar_mult};
use crate::network::nym::types::{MixNode, NYM_HEADER_SIZE, NYM_MAC_SIZE};
use alloc::vec::Vec;

#[derive(Clone)]
pub struct SphinxHeader {
    pub alpha: [u8; 32],
    pub beta: Vec<u8>,
    pub gamma: [u8; NYM_MAC_SIZE],
}

pub fn build_header(
    route: &[MixNode],
    destination: &[u8; 32],
    ephemeral_secret: &[u8; 32],
) -> (SphinxHeader, Vec<[u8; 32]>) {
    let mut alpha = x25519_base_point_mult(ephemeral_secret);
    let mut shared_secrets = Vec::with_capacity(route.len());
    let mut betas = Vec::new();
    let mut blinded_secret = *ephemeral_secret;
    for node in route.iter() {
        let shared = x25519_scalar_mult(&blinded_secret, &node.sphinx_key);
        shared_secrets.push(shared);
        let keys = derive_sphinx_keys(&shared);
        let routing = encode_routing_info(&node.id.0, node.mix_port);
        betas.extend_from_slice(&routing);
        blinded_secret = multiply_scalars(&blinded_secret, &keys.blinding_factor);
        alpha = blind_public_key(&alpha, &keys.blinding_factor);
    }
    betas.extend_from_slice(destination);
    betas.resize(NYM_HEADER_SIZE - 32 - NYM_MAC_SIZE, 0);
    let gamma = compute_header_mac(&shared_secrets[0], &betas);
    (SphinxHeader { alpha, beta: betas, gamma }, shared_secrets)
}

fn encode_routing_info(node_id: &[u8; 32], port: u16) -> [u8; 34] {
    let mut info = [0u8; 34];
    info[..32].copy_from_slice(node_id);
    info[32..34].copy_from_slice(&port.to_be_bytes());
    info
}

fn compute_header_mac(key: &[u8; 32], data: &[u8]) -> [u8; NYM_MAC_SIZE] {
    let hash = crate::crypto::hash::blake3_keyed_hash(key, data);
    let mut mac = [0u8; NYM_MAC_SIZE];
    mac.copy_from_slice(&hash[..NYM_MAC_SIZE]);
    mac
}

fn multiply_scalars(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i].wrapping_mul(b[i]);
    }
    result
}
