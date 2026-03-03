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


use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::types::{
    StreamEndReason, StreamId, StreamProtocol, StreamState,
    DEFAULT_STREAM_QUANTUM_CELLS, MAX_RECV_BUFFER_SIZE, MAX_SEND_BUFFER_SIZE,
    RELAY_PAYLOAD_SIZE, STREAM_SENDME_INCREMENT, STREAM_SENDME_WINDOW,
};
use super::util::{current_time_ms, send_cell};
use crate::network::onion::cell::Cell;
use crate::network::onion::{CircuitId, OnionError};

#[derive(Debug)]
pub struct OnionStream {
    pub stream_id: StreamId,
    pub circuit_id: CircuitId,
    pub state: StreamState,
    pub target_host: String,
    pub target_port: u16,
    pub created_time: u64,
    pub last_activity: u64,

    pub send_window: i32,
    pub recv_window: i32,
    pub package_window: i32,
    pub deliver_window: i32,

    pub send_buffer: Vec<u8>,
    pub recv_buffer: Vec<u8>,

    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub cells_sent: AtomicU32,
    pub cells_received: AtomicU32,

    pub protocol: StreamProtocol,
    pub application_data: BTreeMap<String, Vec<u8>>,

    pub deficit: i32,
}

impl OnionStream {
    pub fn new(stream_id: StreamId, circuit_id: CircuitId, target: String, port: u16, protocol: StreamProtocol) -> Self {
        let now = current_time_ms();
        Self {
            stream_id,
            circuit_id,
            state: StreamState::NewConnect,
            target_host: target,
            target_port: port,
            created_time: now,
            last_activity: now,
            send_window: STREAM_SENDME_WINDOW,
            recv_window: STREAM_SENDME_WINDOW,
            package_window: STREAM_SENDME_WINDOW,
            deliver_window: STREAM_SENDME_WINDOW,
            send_buffer: Vec::new(),
            recv_buffer: Vec::new(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            cells_sent: AtomicU32::new(0),
            cells_received: AtomicU32::new(0),
            protocol,
            application_data: BTreeMap::new(),
            deficit: DEFAULT_STREAM_QUANTUM_CELLS,
        }
    }

    pub fn new_resolve(stream_id: StreamId, circuit_id: CircuitId, hostname: String) -> Self {
        let mut s = Self::new(stream_id, circuit_id, hostname, 0, StreamProtocol::DNS);
        s.state = StreamState::NewResolve;
        s
    }

    #[inline]
    pub fn is_open(&self) -> bool {
        self.state == StreamState::Open
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }

    #[inline]
    pub fn update_activity(&mut self) {
        self.last_activity = current_time_ms();
    }

    pub fn send_data(&mut self, data: &[u8]) -> Result<(), OnionError> {
        if self.state != StreamState::Open {
            return Err(OnionError::StreamClosed);
        }
        if self.send_window <= 0 || self.package_window <= 0 {
            if self.send_buffer.len() + data.len() > MAX_SEND_BUFFER_SIZE {
                return Err(OnionError::NetworkError);
            }
            self.send_buffer.extend_from_slice(data);
            self.update_activity();
            return Ok(());
        }
        self.flush_data(data)?;
        self.update_activity();
        Ok(())
    }

    pub fn recv_data(&mut self) -> Result<Vec<u8>, OnionError> {
        if self.recv_buffer.is_empty() {
            return Ok(Vec::new());
        }
        let out = core::mem::take(&mut self.recv_buffer);

        self.deliver_window -= num_cells_for_len(out.len());
        if self.deliver_window <= STREAM_SENDME_WINDOW - STREAM_SENDME_INCREMENT {
            self.enqueue_sendme()?;
            self.deliver_window += STREAM_SENDME_INCREMENT;
        }
        self.update_activity();
        Ok(out)
    }

    pub fn handle_data_cell(&mut self, data: Vec<u8>) -> Result<(), OnionError> {
        if self.state != StreamState::Open {
            return Err(OnionError::StreamClosed);
        }
        if self.recv_window <= 0 {
            return Err(OnionError::NetworkError);
        }
        if self.recv_buffer.len() + data.len() > MAX_RECV_BUFFER_SIZE {
            return Err(OnionError::NetworkError);
        }

        self.recv_buffer.extend_from_slice(&data);
        self.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.cells_received.fetch_add(1, Ordering::Relaxed);
        self.recv_window -= 1;

        if self.recv_window <= STREAM_SENDME_WINDOW - STREAM_SENDME_INCREMENT {
            self.enqueue_sendme()?;
            self.recv_window += STREAM_SENDME_INCREMENT;
        }

        self.update_activity();
        Ok(())
    }

    pub fn handle_connected(&mut self, addr: [u8; 4], ttl: u32) -> Result<(), OnionError> {
        match self.state {
            StreamState::SentConnect => {
                self.state = StreamState::Open;
                self.application_data.insert("connected_addr".into(), addr.to_vec());
                self.application_data.insert("ttl".into(), ttl.to_be_bytes().to_vec());
                self.update_activity();
                Ok(())
            }
            _ => Err(OnionError::InvalidCell),
        }
    }

    pub fn handle_resolved(&mut self, addresses: Vec<[u8; 4]>, ttl: u32) -> Result<(), OnionError> {
        match self.state {
            StreamState::SentResolve => {
                self.state = StreamState::Open;
                let mut buf = Vec::with_capacity(addresses.len() * 4);
                for a in addresses {
                    buf.extend_from_slice(&a);
                }
                self.application_data.insert("resolved_addresses".into(), buf);
                self.application_data.insert("resolution_ttl".into(), ttl.to_be_bytes().to_vec());
                self.update_activity();
                Ok(())
            }
            _ => Err(OnionError::InvalidCell),
        }
    }

    pub fn handle_end(&mut self, reason: StreamEndReason) -> Result<(), OnionError> {
        self.state = StreamState::Closed;
        self.application_data.insert("end_reason".into(), vec![reason as u8]);
        self.update_activity();
        Ok(())
    }

    pub fn handle_sendme(&mut self) {
        self.send_window += STREAM_SENDME_INCREMENT;
        self.package_window += STREAM_SENDME_INCREMENT;
        self.deficit += DEFAULT_STREAM_QUANTUM_CELLS;
    }

    pub fn flush_data(&mut self, data: &[u8]) -> Result<(), OnionError> {
        if data.is_empty() {
            return Ok(());
        }

        let mut remaining = data;
        while !remaining.is_empty() && self.send_window > 0 && self.package_window > 0 && self.deficit > 0 {
            let take = min(remaining.len(), RELAY_PAYLOAD_SIZE);
            let chunk = &remaining[..take];

            let cell = Cell::relay_data_cell(self.circuit_id, self.stream_id, chunk.to_vec());
            send_cell(cell)?;

            self.send_window -= 1;
            self.package_window -= 1;
            self.deficit -= 1;

            self.bytes_sent.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            self.cells_sent.fetch_add(1, Ordering::Relaxed);
            remaining = &remaining[take..];
        }

        if !remaining.is_empty() {
            if self.send_buffer.len() + remaining.len() > MAX_SEND_BUFFER_SIZE {
                return Err(OnionError::NetworkError);
            }
            self.send_buffer.extend_from_slice(remaining);
        }

        Ok(())
    }

    pub fn try_flush_buffered(&mut self) -> Result<bool, OnionError> {
        if self.send_buffer.is_empty() || self.send_window <= 0 || self.package_window <= 0 || self.deficit <= 0 {
            return Ok(false);
        }

        let mut emitted_any = false;
        while !self.send_buffer.is_empty() && self.send_window > 0 && self.package_window > 0 && self.deficit > 0 {
            let take = min(self.send_buffer.len(), RELAY_PAYLOAD_SIZE);
            let chunk: Vec<u8> = self.send_buffer.drain(..take).collect();

            let cell = Cell::relay_data_cell(self.circuit_id, self.stream_id, chunk.clone());
            send_cell(cell)?;

            self.send_window -= 1;
            self.package_window -= 1;
            self.deficit -= 1;

            self.bytes_sent.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            self.cells_sent.fetch_add(1, Ordering::Relaxed);
            emitted_any = true;
        }
        Ok(emitted_any)
    }

    fn enqueue_sendme(&mut self) -> Result<(), OnionError> {
        let cell = Cell::relay_data_cell(self.circuit_id, self.stream_id, Vec::new());
        send_cell(cell)
    }
}

#[inline]
fn num_cells_for_len(len: usize) -> i32 {
    ((len + RELAY_PAYLOAD_SIZE - 1) / RELAY_PAYLOAD_SIZE) as i32
}
