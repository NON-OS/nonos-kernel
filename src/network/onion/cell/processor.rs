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


use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use crate::network::onion::{CircuitId, OnionError, StreamId};
use crate::network::onion::circuit::CircuitManager;
use crate::network::onion::stream::StreamManager;
use super::types::{CellType, RelayCommand, CELL_PAYLOAD_SIZE};
use super::cell::{Cell, RelayCell};

#[derive(Debug, Default)]
pub struct CellStatistics {
    pub cells_processed: AtomicU16,
    pub relay_cells_processed: AtomicU16,
    pub create_cells_processed: AtomicU16,
    pub destroy_cells_processed: AtomicU16,
    pub data_bytes_transferred: AtomicU16,
}

pub struct CellProcessor {
    pending_cells: Mutex<BTreeMap<CircuitId, Vec<Cell>>>,
    stream_id_counter: AtomicU16,
    statistics: CellStatistics,
}

impl CellProcessor {
    pub fn new() -> Self {
        CellProcessor {
            pending_cells: Mutex::new(BTreeMap::new()),
            stream_id_counter: AtomicU16::new(1),
            statistics: CellStatistics::default(),
        }
    }

    pub fn process_cell(
        &mut self,
        cell: Cell,
        circuit_manager: &mut CircuitManager,
        stream_manager: &mut StreamManager,
    ) -> Result<(), OnionError> {
        self.statistics.cells_processed.fetch_add(1, Ordering::Relaxed);

        match cell.command {
            c if c == CellType::Create as u8 => self.handle_create_cell(cell, circuit_manager),
            c if c == CellType::Create2 as u8 => self.handle_create2_cell(cell, circuit_manager),
            c if c == CellType::Created as u8 => self.handle_created_cell(cell, circuit_manager),
            c if c == CellType::Created2 as u8 => self.handle_created2_cell(cell, circuit_manager),

            c if c == CellType::Relay as u8 || c == CellType::RelayEarly as u8 => {
                self.handle_relay_cell(cell, circuit_manager, stream_manager)
            }

            c if c == CellType::Destroy as u8 => self.handle_destroy_cell(cell, circuit_manager),

            c if c == CellType::Padding as u8 || c == CellType::VPadding as u8 => Ok(()),

            _ => Err(OnionError::InvalidCell),
        }
    }

    #[inline]
    fn handle_create_cell(&self, _cell: Cell, _circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        self.statistics
            .create_cells_processed
            .fetch_add(1, Ordering::Relaxed);
        crate::log_warn!("cell: received CREATE cell in client mode, rejecting");
        Err(OnionError::InvalidCell)
    }

    #[inline]
    fn handle_create2_cell(&self, _cell: Cell, _circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        self.statistics
            .create_cells_processed
            .fetch_add(1, Ordering::Relaxed);
        crate::log_warn!("cell: received CREATE2 cell in client mode, rejecting");
        Err(OnionError::InvalidCell)
    }

    #[inline]
    fn handle_created_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        circuit_manager.handle_created_cell(cell.circuit_id, cell)
    }

    #[inline]
    fn handle_created2_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        circuit_manager.handle_created_cell(cell.circuit_id, cell)
    }

    fn handle_relay_cell(
        &self,
        cell: Cell,
        circuit_manager: &mut CircuitManager,
        stream_manager: &mut StreamManager,
    ) -> Result<(), OnionError> {
        self.statistics
            .relay_cells_processed
            .fetch_add(1, Ordering::Relaxed);

        let decrypted_cell = if let Some(circuit) = circuit_manager.get_circuit(cell.circuit_id) {
            let mut dec = cell.clone();
            dec.payload = circuit.decrypt_backward(&cell.payload)?;
            dec
        } else {
            return Err(OnionError::CircuitBuildFailed);
        };

        let relay_cell = decrypted_cell.parse_relay_cell()?;

        match relay_cell.header.command {
            RelayCommand::RelayData => {
                self.statistics
                    .data_bytes_transferred
                    .fetch_add(relay_cell.payload.len() as u16, Ordering::Relaxed);
                stream_manager.handle_data(relay_cell.header.stream_id, &relay_cell.payload)
            }
            RelayCommand::RelayBegin => stream_manager.handle_begin(relay_cell),
            RelayCommand::RelayConnected => stream_manager.handle_connected(relay_cell),
            RelayCommand::RelayEnd => stream_manager.handle_end(relay_cell),

            RelayCommand::RelayExtended | RelayCommand::RelayExtended2 => {
                let mut tmp = Cell {
                    circuit_id: cell.circuit_id,
                    command: CellType::Relay as u8,
                    payload: relay_cell.payload.clone(),
                    is_variable_length: false,
                };
                if tmp.payload.len() < CELL_PAYLOAD_SIZE {
                    tmp.payload.resize(CELL_PAYLOAD_SIZE, 0);
                }
                circuit_manager.handle_extended_cell(cell.circuit_id, tmp)
            }

            RelayCommand::RelaySendme => Ok(()),
            RelayCommand::RelayDrop => Ok(()),

            RelayCommand::RelayResolve => self.handle_resolve(relay_cell, cell.circuit_id),
            RelayCommand::RelayResolved => self.handle_resolved(relay_cell, stream_manager),

            _ => Err(OnionError::InvalidCell),
        }
    }

    #[inline]
    fn handle_destroy_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        self.statistics
            .destroy_cells_processed
            .fetch_add(1, Ordering::Relaxed);
        circuit_manager.close_circuit(cell.circuit_id)
    }

    fn handle_resolve(&self, relay_cell: RelayCell, circuit_id: CircuitId) -> Result<(), OnionError> {
        crate::log_warn!(
            "cell: received RELAY_RESOLVE on circuit {} stream {} in client mode",
            circuit_id,
            relay_cell.header.stream_id
        );
        Err(OnionError::InvalidCell)
    }

    fn handle_resolved(&self, relay_cell: RelayCell, stream_manager: &mut StreamManager) -> Result<(), OnionError> {
        let stream_id = relay_cell.header.stream_id;
        let payload = &relay_cell.payload;

        if payload.is_empty() {
            crate::log_warn!("cell: empty RELAY_RESOLVED payload for stream {}", stream_id);
            return Err(OnionError::InvalidCell);
        }

        let mut addrs = Vec::new();
        let mut pos = 0;

        while pos < payload.len() {
            if pos + 2 > payload.len() {
                break;
            }
            let addr_type = payload[pos];
            let addr_len = payload[pos + 1] as usize;
            pos += 2;

            if pos + addr_len > payload.len() {
                break;
            }

            match addr_type {
                0x04 => {
                    if addr_len >= 4 {
                        let addr = [
                            payload[pos],
                            payload[pos + 1],
                            payload[pos + 2],
                            payload[pos + 3],
                        ];
                        addrs.push(addr);
                    }
                }
                0x06 => {
                }
                0xF0 => {
                    crate::log_warn!("cell: RELAY_RESOLVED error for stream {}", stream_id);
                }
                _ => {
                }
            }

            pos += addr_len;
            if pos + 4 <= payload.len() {
                pos += 4;
            }
        }

        stream_manager.handle_data(stream_id, &relay_cell.payload)
    }

    pub fn next_stream_id(&self) -> StreamId {
        self.stream_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn get_statistics(&self) -> &CellStatistics {
        &self.statistics
    }

    pub fn queue_cell(&self, circuit_id: CircuitId, cell: Cell) {
        if let Some(mut pending) = self.pending_cells.try_lock() {
            pending.entry(circuit_id).or_insert_with(Vec::new).push(cell);
        }
    }

    pub fn flush_circuit_cells(&self, circuit_id: CircuitId) -> Vec<Cell> {
        if let Some(mut pending) = self.pending_cells.try_lock() {
            pending.remove(&circuit_id).unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}
