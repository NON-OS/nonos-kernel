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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::manager_core::StreamManager;
use super::onion_stream::OnionStream;
use super::types::{StreamEndReason, StreamState};
use super::util::current_time_ms;
use crate::network::onion::cell::{RelayCell, RelayCommand};
use crate::network::onion::{CircuitId, OnionError};

impl StreamManager {
    pub fn handle_relay_cell(&self, circuit_id: CircuitId, relay: RelayCell) -> Result<(), OnionError> {
        match relay.header.command {
            RelayCommand::RelayData => {
                let sid = relay.header.stream_id;
                let mut map = self.streams.lock();
                if let Some(s) = map.get_mut(&sid) {
                    s.handle_data_cell(relay.payload)?;
                }
            }
            RelayCommand::RelayConnected => {
                let sid = relay.header.stream_id;
                let mut map = self.streams.lock();
                if let Some(s) = map.get_mut(&sid) {
                    if relay.payload.len() >= 8 {
                        let addr = [relay.payload[0], relay.payload[1], relay.payload[2], relay.payload[3]];
                        let ttl = u32::from_be_bytes([relay.payload[4], relay.payload[5], relay.payload[6], relay.payload[7]]);
                        s.handle_connected(addr, ttl)?;
                    } else {
                        s.handle_connected([0, 0, 0, 0], 0)?;
                    }
                }
            }
            RelayCommand::RelayResolved => {
                let sid = relay.header.stream_id;
                let mut map = self.streams.lock();
                if let Some(s) = map.get_mut(&sid) {
                    let mut addrs = Vec::new();
                    for chunk in relay.payload.chunks_exact(4) {
                        addrs.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    }
                    s.handle_resolved(addrs, 60)?;
                }
            }
            RelayCommand::RelayEnd => {
                let sid = relay.header.stream_id;
                let mut map = self.streams.lock();
                if let Some(s) = map.get_mut(&sid) {
                    let reason = relay.payload.first().copied().unwrap_or(0);
                    s.handle_end(StreamEndReason::from_u8(reason))?;
                    if s.is_closed() {
                        map.remove(&sid);
                        drop(map);
                        self.remove_from_circuit(circuit_id, sid);
                        self.stream_stats.active_streams.fetch_sub(1, Ordering::Relaxed);
                        self.stream_stats.total_streams_closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            RelayCommand::RelaySendme => {
                let sid = relay.header.stream_id;
                if sid == 0 {
                    self.flow.handle_circuit_sendme(circuit_id);
                } else {
                    let mut map = self.streams.lock();
                    if let Some(s) = map.get_mut(&sid) {
                        s.handle_sendme();
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn handle_data(&mut self, stream_id: super::types::StreamId, data: &[u8]) -> Result<(), OnionError> {
        let mut streams = self.streams.lock();
        if let Some(stream) = streams.get_mut(&stream_id) {
            stream.recv_buffer.extend_from_slice(data);
            stream.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            Err(OnionError::StreamNotFound)
        }
    }

    pub fn handle_begin(&mut self, cell: RelayCell) -> Result<(), OnionError> {
        let stream_id = cell.header.stream_id;
        let circuit_id = cell.circuit_id;

        let payload = &cell.payload;
        let null_pos = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
        let addr_str = core::str::from_utf8(&payload[..null_pos])
            .map_err(|_| OnionError::InvalidCell)?;

        let (target, port) = if let Some(colon_pos) = addr_str.rfind(':') {
            let host = &addr_str[..colon_pos];
            let port_str = &addr_str[colon_pos + 1..];
            let port = port_str.parse::<u16>().map_err(|_| OnionError::InvalidCell)?;
            (String::from(host), port)
        } else {
            return Err(OnionError::InvalidCell);
        };

        let protocol = self.detect_protocol(&target, port);
        let stream = OnionStream::new(stream_id, circuit_id, target.clone(), port, protocol);

        self.streams.lock().insert(stream_id, stream);
        self.by_circuit.lock().entry(circuit_id).or_insert_with(Vec::new).push(stream_id);

        self.stream_stats.active_streams.fetch_add(1, Ordering::Relaxed);
        self.stream_stats.total_streams_created.fetch_add(1, Ordering::Relaxed);

        crate::log::info!("stream: BEGIN stream {} on circuit {} -> {}:{}", stream_id, circuit_id, target, port);
        Ok(())
    }

    pub fn handle_connected(&mut self, cell: RelayCell) -> Result<(), OnionError> {
        let stream_id = cell.header.stream_id;

        let mut streams = self.streams.lock();
        if let Some(stream) = streams.get_mut(&stream_id) {
            stream.state = StreamState::Open;
            stream.last_activity = current_time_ms();

            crate::log::info!("stream: CONNECTED stream {} -> {}:{}", stream_id, stream.target_host, stream.target_port);
            Ok(())
        } else {
            Err(OnionError::StreamNotFound)
        }
    }

    pub fn handle_end(&mut self, cell: RelayCell) -> Result<(), OnionError> {
        let stream_id = cell.header.stream_id;

        let reason = if !cell.payload.is_empty() {
            cell.payload[0]
        } else {
            0
        };

        let mut streams = self.streams.lock();
        if let Some(stream) = streams.get_mut(&stream_id) {
            let circuit_id = stream.circuit_id;
            stream.state = StreamState::Closed;

            crate::log::info!("stream: END stream {} (reason: {})", stream_id, reason);

            drop(streams);
            self.remove_from_circuit(circuit_id, stream_id);

            self.stream_stats.active_streams.fetch_sub(1, Ordering::Relaxed);
            self.stream_stats.total_streams_closed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}
