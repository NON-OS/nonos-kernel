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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use super::flow::FlowControlManager;
use super::onion_stream::OnionStream;
use super::protocol::ProtocolHandlerRegistry;
use super::stats::{StreamMetrics, StreamStatistics};
use super::types::{
    StreamEndReason, StreamId, StreamProtocol, StreamState, DEFAULT_STREAM_QUANTUM_CELLS,
};
use super::util::current_time_ms;
use crate::network::onion::cell::Cell;
use crate::network::onion::{CircuitId, OnionError};

pub struct StreamManager {
    pub(super) streams: Mutex<BTreeMap<StreamId, OnionStream>>,
    pub(super) by_circuit: Mutex<BTreeMap<CircuitId, Vec<StreamId>>>,
    pub(super) stream_id_counter: AtomicU16,
    pub(super) stream_stats: StreamStatistics,
    pub(super) flow: FlowControlManager,
    pub(super) proto: ProtocolHandlerRegistry,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            streams: Mutex::new(BTreeMap::new()),
            by_circuit: Mutex::new(BTreeMap::new()),
            stream_id_counter: AtomicU16::new(1),
            stream_stats: StreamStatistics::default(),
            flow: FlowControlManager::new(),
            proto: ProtocolHandlerRegistry::new(),
        }
    }

    pub fn create_stream(&self, circuit_id: CircuitId, target: String, port: u16) -> Result<StreamId, OnionError> {
        let sid = self.next_stream_id();
        let proto = self.detect_protocol(&target, port);
        let mut s = OnionStream::new(sid, circuit_id, target.clone(), port, proto);

        let cell = Cell::relay_begin_cell(circuit_id, sid, target, port);
        super::util::send_cell(cell)?;

        s.state = StreamState::SentConnect;

        self.streams.lock().insert(sid, s);
        self.by_circuit.lock().entry(circuit_id).or_default().push(sid);

        self.stream_stats.active_streams.fetch_add(1, Ordering::Relaxed);
        self.stream_stats.total_streams_created.fetch_add(1, Ordering::Relaxed);
        Ok(sid)
    }

    pub fn create_resolve_stream(&self, circuit_id: CircuitId, hostname: String) -> Result<StreamId, OnionError> {
        let sid = self.next_stream_id();
        let mut s = OnionStream::new_resolve(sid, circuit_id, hostname.clone());

        let mut payload = hostname.into_bytes();
        payload.push(0);

        let cell = Cell::relay_data_cell(circuit_id, sid, payload);
        super::util::send_cell(cell)?;
        s.state = StreamState::SentResolve;

        self.streams.lock().insert(sid, s);
        self.by_circuit.lock().entry(circuit_id).or_default().push(sid);

        self.stream_stats.active_streams.fetch_add(1, Ordering::Relaxed);
        self.stream_stats.total_streams_created.fetch_add(1, Ordering::Relaxed);
        Ok(sid)
    }

    pub fn send_data(&self, stream_id: StreamId, data: &[u8]) -> Result<(), OnionError> {
        let mut map = self.streams.lock();
        let s = map.get_mut(&stream_id).ok_or(OnionError::StreamClosed)?;
        s.send_data(data)?;
        self.stream_stats.total_data_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub fn recv_data(&self, stream_id: StreamId) -> Result<Vec<u8>, OnionError> {
        let mut map = self.streams.lock();
        let s = map.get_mut(&stream_id).ok_or(OnionError::StreamClosed)?;
        let out = s.recv_data()?;
        if !out.is_empty() {
            self.stream_stats.total_data_transferred.fetch_add(out.len() as u64, Ordering::Relaxed);
        }
        Ok(out)
    }

    pub fn close_stream(&self, stream_id: StreamId, reason: StreamEndReason) -> Result<(), OnionError> {
        let mut map = self.streams.lock();
        if let Some(s) = map.get_mut(&stream_id) {
            if s.state == StreamState::Closed {
                return Ok(());
            }
            let cell = Cell::relay_end_cell(s.circuit_id, s.stream_id, reason as u8);
            super::util::send_cell(cell)?;
            s.state = StreamState::ExitWait;
        }
        Ok(())
    }

    pub fn tick(&self, circuit_id: CircuitId) {
        if let Some(ids) = self.by_circuit.lock().get(&circuit_id).cloned() {
            let mut map = self.streams.lock();
            for sid in ids.iter() {
                if let Some(s) = map.get_mut(sid) {
                    if s.deficit <= 0 {
                        s.deficit += DEFAULT_STREAM_QUANTUM_CELLS;
                    }
                }
            }
        }

        if let Some(ids) = self.by_circuit.lock().get(&circuit_id).cloned() {
            let mut map = self.streams.lock();
            for sid in ids {
                if let Some(s) = map.get_mut(&sid) {
                    if self.flow.can_package_on_circuit(circuit_id) {
                        if let Ok(emitted) = s.try_flush_buffered() {
                            if emitted {
                                self.flow.on_circuit_pack(circuit_id, 1);
                            }
                        }
                    }
                }
            }
        }

        self.flow.cc_tick(circuit_id);
    }

    pub fn stream_metrics(&self, stream_id: StreamId) -> Option<StreamMetrics> {
        let map = self.streams.lock();
        map.get(&stream_id).map(|s| StreamMetrics {
            bytes_sent: s.bytes_sent.load(Ordering::Relaxed),
            bytes_received: s.bytes_received.load(Ordering::Relaxed),
            cells_sent: s.cells_sent.load(Ordering::Relaxed),
            cells_received: s.cells_received.load(Ordering::Relaxed),
            uptime_ms: current_time_ms().saturating_sub(s.created_time),
            send_buffer_size: s.send_buffer.len(),
            recv_buffer_size: s.recv_buffer.len(),
            send_window: s.send_window,
            recv_window: s.recv_window,
        })
    }

    pub fn get_active_streams(&self) -> Vec<StreamId> {
        self.streams.lock()
            .iter()
            .filter(|(_, s)| s.is_open())
            .map(|(k, _)| *k)
            .collect()
    }

    pub fn get_statistics(&self) -> &StreamStatistics {
        &self.stream_stats
    }

    pub fn cleanup_closed_streams(&self) {
        let map = self.streams.lock();
        let to_remove: Vec<_> = map.iter()
            .filter(|(_, s)| s.is_closed())
            .map(|(sid, _)| *sid)
            .collect();
        drop(map);

        if !to_remove.is_empty() {
            let mut map = self.streams.lock();
            for sid in to_remove {
                if let Some(s) = map.remove(&sid) {
                    drop(map);
                    self.remove_from_circuit(s.circuit_id, sid);
                    self.stream_stats.active_streams.fetch_sub(1, Ordering::Relaxed);
                    map = self.streams.lock();
                }
            }
        }
    }

    pub(super) fn detect_protocol(&self, target: &str, port: u16) -> StreamProtocol {
        match port {
            80 | 443 => StreamProtocol::HTTP,
            53 => StreamProtocol::DNS,
            _ => {
                if target.ends_with(".onion") {
                    StreamProtocol::Directory
                } else {
                    StreamProtocol::TCP
                }
            }
        }
    }

    pub(super) fn next_stream_id(&self) -> StreamId {
        self.stream_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn remove_from_circuit(&self, circuit_id: CircuitId, sid: StreamId) {
        let mut idx = self.by_circuit.lock();
        if let Some(v) = idx.get_mut(&circuit_id) {
            if let Some(pos) = v.iter().position(|x| *x == sid) {
                v.swap_remove(pos);
            }
        }
    }
}
