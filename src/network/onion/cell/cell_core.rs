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

use alloc::{vec, vec::Vec};
use crate::network::onion::{CircuitId, OnionError};
use super::types::{
    CellType, RelayCommand, CELL_PAYLOAD_SIZE, CELL_SIZE, CELL_HEADER_SIZE,
    VAR_CELL_HEADER_SIZE, MAX_VAR_CELL_PAYLOAD_SIZE, RELAY_HEADER_SIZE, RELAY_PAYLOAD_SIZE,
};
use super::cell_relay::{RelayCell, RelayHeader};

#[derive(Debug, Clone)]
pub struct Cell {
    pub circuit_id: CircuitId,
    pub command: u8,
    pub payload: Vec<u8>,
    pub is_variable_length: bool,
}

impl Cell {
    pub fn new(circuit_id: CircuitId, command: CellType, payload: Vec<u8>) -> Self {
        let mut cell_payload = payload;
        cell_payload.resize(CELL_PAYLOAD_SIZE, 0);
        Cell {
            circuit_id,
            command: command as u8,
            payload: cell_payload,
            is_variable_length: false,
        }
    }

    pub fn new_var(circuit_id: CircuitId, command: CellType, payload: Vec<u8>) -> Self {
        Cell {
            circuit_id,
            command: command as u8,
            payload,
            is_variable_length: true,
        }
    }

    pub fn create_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        Cell::new(circuit_id, CellType::Create, handshake_data)
    }

    pub fn create2_cell(circuit_id: CircuitId, handshake_type: u16, handshake_data: Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(4 + handshake_data.len());
        payload.extend_from_slice(&handshake_type.to_be_bytes());
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        Cell::new_var(circuit_id, CellType::Create2, payload)
    }

    pub fn created_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        Cell::new(circuit_id, CellType::Created, handshake_data)
    }

    pub fn created2_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(2 + handshake_data.len());
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        Cell::new_var(circuit_id, CellType::Created2, payload)
    }

    pub fn destroy_cell(circuit_id: CircuitId, reason: u8) -> Self {
        Cell::new(circuit_id, CellType::Destroy, vec![reason])
    }

    pub fn from_relay_cell(relay_cell: RelayCell) -> Self {
        let mut payload = Vec::with_capacity(CELL_PAYLOAD_SIZE);

        payload.push(relay_cell.header.command as u8);
        payload.extend_from_slice(&relay_cell.header.recognized.to_be_bytes());
        payload.extend_from_slice(&relay_cell.header.stream_id.to_be_bytes());
        payload.extend_from_slice(&relay_cell.header.digest);
        payload.extend_from_slice(&relay_cell.header.length.to_be_bytes());

        payload.extend_from_slice(&relay_cell.payload);

        payload.resize(CELL_PAYLOAD_SIZE, 0);

        Cell {
            circuit_id: relay_cell.circuit_id,
            command: CellType::Relay as u8,
            payload,
            is_variable_length: false,
        }
    }

    pub fn parse_relay_cell(&self) -> Result<RelayCell, OnionError> {
        if self.command != CellType::Relay as u8 && self.command != CellType::RelayEarly as u8 {
            return Err(OnionError::InvalidCell);
        }
        if self.payload.len() < RELAY_HEADER_SIZE {
            return Err(OnionError::InvalidCell);
        }

        let command = RelayCommand::from_u8(self.payload[0])?;
        let recognized = u16::from_be_bytes([self.payload[1], self.payload[2]]);
        let stream_id = u16::from_be_bytes([self.payload[3], self.payload[4]]);
        let mut digest = [0u8; 4];
        digest.copy_from_slice(&self.payload[5..9]);
        let length = u16::from_be_bytes([self.payload[9], self.payload[10]]);

        if length as usize > RELAY_PAYLOAD_SIZE {
            return Err(OnionError::InvalidCell);
        }

        let payload_end = RELAY_HEADER_SIZE + length as usize;
        if payload_end > self.payload.len() {
            return Err(OnionError::InvalidCell);
        }

        Ok(RelayCell {
            circuit_id: self.circuit_id,
            header: RelayHeader {
                command,
                recognized,
                stream_id,
                digest,
                length,
            },
            payload: self.payload[RELAY_HEADER_SIZE..payload_end].to_vec(),
            hop_level: 0,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.circuit_id.to_be_bytes());
        data.push(self.command);

        if self.is_variable_length {
            data.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.payload);
        } else {
            let mut payload = self.payload.clone();
            payload.resize(CELL_PAYLOAD_SIZE, 0);
            data.extend_from_slice(&payload);
        }
        data
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, OnionError> {
        if data.len() < CELL_HEADER_SIZE {
            return Err(OnionError::InvalidCell);
        }
        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let command = data[4];

        let is_var_length = Self::is_variable_length_command(command);

        if is_var_length {
            if data.len() < VAR_CELL_HEADER_SIZE {
                return Err(OnionError::InvalidCell);
            }
            let payload_len = u16::from_be_bytes([data[5], data[6]]) as usize;
            if data.len() < VAR_CELL_HEADER_SIZE + payload_len || payload_len > MAX_VAR_CELL_PAYLOAD_SIZE {
                return Err(OnionError::InvalidCell);
            }
            let payload = data[VAR_CELL_HEADER_SIZE..VAR_CELL_HEADER_SIZE + payload_len].to_vec();
            Ok(Cell {
                circuit_id,
                command,
                payload,
                is_variable_length: true,
            })
        } else {
            if data.len() != CELL_SIZE {
                return Err(OnionError::InvalidCell);
            }
            let payload = data[CELL_HEADER_SIZE..].to_vec();
            Ok(Cell {
                circuit_id,
                command,
                payload,
                is_variable_length: false,
            })
        }
    }

    #[inline]
    fn is_variable_length_command(command: u8) -> bool {
        matches!(command, c if c == CellType::Versions as u8
            || c == CellType::NetInfo as u8
            || c == CellType::Create2 as u8
            || c == CellType::Created2 as u8
            || (128..=132).contains(&c))
    }
}
