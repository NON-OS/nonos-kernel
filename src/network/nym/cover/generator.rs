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

use crate::network::nym::error::NymError;
use crate::network::nym::route::build_route;
use crate::network::nym::sphinx::{build_packet, SphinxPacket};
use crate::network::nym::types::{NymAddress, NYM_PAYLOAD_SIZE};
use alloc::vec;

pub struct CoverGenerator {
    self_address: NymAddress,
}

pub fn generate_cover_packet(self_address: &NymAddress) -> Result<SphinxPacket, NymError> {
    CoverGenerator::new(self_address.clone()).generate()
}

pub fn generate_drop_cover(destination: &NymAddress) -> Result<SphinxPacket, NymError> {
    let route = build_route(destination)?;
    let mut payload = vec![0u8; NYM_PAYLOAD_SIZE];
    let _ = crate::crypto::random::fill_bytes(&mut payload);
    payload[0] = 0x02;
    build_packet(&route.mixnodes, destination, &payload)
}

impl CoverGenerator {
    pub fn new(self_address: NymAddress) -> Self {
        Self { self_address }
    }

    pub fn generate(&self) -> Result<SphinxPacket, NymError> {
        let route = build_route(&self.self_address)?;
        let mut cover_payload = vec![0u8; NYM_PAYLOAD_SIZE];
        let _ = crate::crypto::random::fill_bytes(&mut cover_payload);
        cover_payload[0] = 0x01;
        build_packet(&route.mixnodes, &self.self_address, &cover_payload)
    }
}
