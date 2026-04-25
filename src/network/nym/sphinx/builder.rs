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

use super::header::build_header;
use super::packet::{PacketMode, SphinxPacket};
use super::payload::encrypt_payload;
use crate::network::nym::crypto::{derive_sphinx_keys, generate_keypair};
use crate::network::nym::error::NymError;
use crate::network::nym::types::{MixNode, NymAddress, Surb};
use alloc::vec::Vec;

pub fn build_packet(
    route: &[MixNode],
    destination: &NymAddress,
    plaintext: &[u8],
) -> Result<SphinxPacket, NymError> {
    if route.is_empty() {
        return Err(NymError::InvalidRoute);
    }
    let (ephemeral_secret, _) = generate_keypair();
    let dest_bytes = destination.to_bytes();
    let mut dest32 = [0u8; 32];
    dest32.copy_from_slice(&dest_bytes[..32]);
    let (header, shared_secrets) = build_header(route, &dest32, &ephemeral_secret);
    let payload_keys: Vec<[u8; 32]> =
        shared_secrets.iter().map(|s| derive_sphinx_keys(s).payload_key).collect();
    let payload = encrypt_payload(plaintext, &payload_keys)?;
    Ok(SphinxPacket::new(header, payload, PacketMode::Forward))
}

pub fn build_surb_packet(surb: &Surb, plaintext: &[u8]) -> Result<SphinxPacket, NymError> {
    let mut payload_data = vec![0u8; 1024];
    if plaintext.len() > 1000 {
        return Err(NymError::PacketTooLarge);
    }
    payload_data[..plaintext.len()].copy_from_slice(plaintext);
    payload_data[plaintext.len()] = 0x80;
    crate::network::nym::crypto::lioness::lioness_encrypt(&surb.payload_key, &mut payload_data);
    let header = super::header::SphinxHeader {
        alpha: [0u8; 32],
        beta: surb.header.clone(),
        gamma: [0u8; 16],
    };
    let payload = super::payload::SphinxPayload::new(payload_data);
    Ok(SphinxPacket::new(header, payload, PacketMode::Surb))
}
