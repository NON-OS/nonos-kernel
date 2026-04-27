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

use super::header::SphinxHeader;
use super::payload::SphinxPayload;
use crate::network::nym::error::NymError;
use crate::network::nym::types::{NYM_HEADER_SIZE, NYM_MAC_SIZE, NYM_PACKET_SIZE};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketMode {
    Forward,
    Surb,
}

#[derive(Clone)]
pub struct SphinxPacket {
    pub header: SphinxHeader,
    pub payload: SphinxPayload,
    pub mode: PacketMode,
}

impl SphinxPacket {
    pub fn new(header: SphinxHeader, payload: SphinxPayload, mode: PacketMode) -> Self {
        Self { header, payload, mode }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NYM_PACKET_SIZE);
        out.push(self.mode as u8);
        out.extend_from_slice(&self.header.alpha);
        out.extend_from_slice(&self.header.gamma);
        out.extend_from_slice(&self.header.beta);
        out.extend_from_slice(&self.payload.data);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, NymError> {
        if data.len() < NYM_HEADER_SIZE + 64 {
            return Err(NymError::InvalidPacket);
        }
        let mode = match data[0] {
            0 => PacketMode::Forward,
            1 => PacketMode::Surb,
            _ => return Err(NymError::InvalidPacket),
        };
        let mut alpha = [0u8; 32];
        alpha.copy_from_slice(&data[1..33]);
        let mut gamma = [0u8; NYM_MAC_SIZE];
        gamma.copy_from_slice(&data[33..33 + NYM_MAC_SIZE]);
        let beta_end = 33 + NYM_MAC_SIZE + NYM_HEADER_SIZE - 32 - NYM_MAC_SIZE;
        let beta = data[33 + NYM_MAC_SIZE..beta_end].to_vec();
        let payload = SphinxPayload::new(data[beta_end..].to_vec());
        let header = SphinxHeader { alpha, beta, gamma };
        Ok(Self { header, payload, mode })
    }
}
