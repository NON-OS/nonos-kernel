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

use alloc::{format, string::String, vec, vec::Vec};
use crate::crypto::hash;
use crate::network::onion::{CircuitId, StreamId};
use crate::network::onion::circuit::{ExtendInfo, LinkSpecifier};
use super::cell_core::Cell;
use super::types::RelayCommand;

#[derive(Debug, Clone)]
pub struct RelayHeader {
    pub command: RelayCommand,
    pub recognized: u16,
    pub stream_id: StreamId,
    pub digest: [u8; 4],
    pub length: u16,
}

#[derive(Debug, Clone)]
pub struct RelayCell {
    pub circuit_id: CircuitId,
    pub header: RelayHeader,
    pub payload: Vec<u8>,
    pub hop_level: u8,
}

impl Cell {
    pub fn extend_cell(circuit_id: CircuitId, extend_info: ExtendInfo, handshake_data: Vec<u8>) -> Self {
        let relay_payload = Self::encode_extend_payload(extend_info, handshake_data);
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtend,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: relay_payload.len() as u16,
            },
            payload: relay_payload,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn extend2_cell(
        circuit_id: CircuitId,
        extend_info: ExtendInfo,
        handshake_type: u16,
        handshake_data: Vec<u8>,
    ) -> Self {
        let relay_payload = Self::encode_extend2_payload(extend_info, handshake_type, handshake_data);
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtend2,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: relay_payload.len() as u16,
            },
            payload: relay_payload,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn extended_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtended,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: handshake_data.len() as u16,
            },
            payload: handshake_data,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn extended2_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(2 + handshake_data.len());
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtended2,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: payload.len() as u16,
            },
            payload,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn relay_data_cell(circuit_id: CircuitId, stream_id: StreamId, data: Vec<u8>) -> Self {
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayData,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: data.len() as u16,
            },
            payload: data,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn relay_begin_cell(circuit_id: CircuitId, stream_id: StreamId, target: String, port: u16) -> Self {
        let mut payload = format!("{}:{}\0", target, port).into_bytes();
        payload.push(0);
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayBegin,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: payload.len() as u16,
            },
            payload,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn relay_connected_cell(circuit_id: CircuitId, stream_id: StreamId, addr: [u8; 4], ttl: u32) -> Self {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&addr);
        payload.extend_from_slice(&ttl.to_be_bytes());
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayConnected,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: payload.len() as u16,
            },
            payload,
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    pub fn relay_end_cell(circuit_id: CircuitId, stream_id: StreamId, reason: u8) -> Self {
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayEnd,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: 1,
            },
            payload: vec![reason],
            hop_level: 0,
        };
        Cell::from_relay_cell(relay_cell)
    }

    fn encode_extend_payload(extend_info: ExtendInfo, handshake_data: Vec<u8>) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&extend_info.address);
        payload.extend_from_slice(&extend_info.port.to_be_bytes());

        let onion_key_hash = hash::blake3_hash(&extend_info.onion_key);
        payload.extend_from_slice(&onion_key_hash[..20]);

        let identity_hash = hash::blake3_hash(&extend_info.identity_key);
        payload.extend_from_slice(&identity_hash[..20]);

        payload.extend_from_slice(&handshake_data);
        payload
    }

    fn encode_extend2_payload(extend_info: ExtendInfo, handshake_type: u16, handshake_data: Vec<u8>) -> Vec<u8> {
        let mut payload = Vec::new();

        payload.push(extend_info.link_specifiers.len() as u8);

        for spec in &extend_info.link_specifiers {
            match spec {
                LinkSpecifier::IPv4 { addr, port } => {
                    payload.push(0);
                    payload.push(6);
                    payload.extend_from_slice(addr);
                    payload.extend_from_slice(&port.to_be_bytes());
                }
                LinkSpecifier::IPv6 { addr, port } => {
                    payload.push(1);
                    payload.push(18);
                    payload.extend_from_slice(addr);
                    payload.extend_from_slice(&port.to_be_bytes());
                }
                LinkSpecifier::Legacy { identity } => {
                    payload.push(2);
                    payload.push(20);
                    payload.extend_from_slice(identity);
                }
                LinkSpecifier::Ed25519 { identity } => {
                    payload.push(3);
                    payload.push(32);
                    payload.extend_from_slice(identity);
                }
            }
        }

        payload.extend_from_slice(&handshake_type.to_be_bytes());
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        payload
    }
}
