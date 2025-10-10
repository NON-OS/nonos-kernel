#![no_std]

/*!
TorOnion Stream Management

 - Multiplex many streams over a circuit
 - Stream & circuit flow control with SENDME (Tor semantics)
 - Fair scheduler (round-robin + deficit/quantum)
 - Congestion-control pluggable (Fixed, AIMD, Vegas stubs)
 - Protocol handler registry (HTTP/DNS/Custom hooks)
 - Robust handling of CONNECTED / DATA / RESOLVED / END / SENDME (stream & circuit)

 Notes:
 - We keep RELAY payload size at 498 bytes (Tor spec).
 - For sending SENDME, this module uses a helper that falls back to a DATA(0) cell if a dedicated SENDME constructor is not present in `Cell`.
*/

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::cell::{Cell, RelayCell, RelayCommand};
use super::{CircuitId, OnionError};
use crate::network::get_network_stack;

pub type StreamId = u16;

/* ============================================================
Constants
============================================================ */

/// Payload bytes per RELAY cell (Tor v3)
const RELAY_PAYLOAD_SIZE: usize = 498;

/// Stream default windows (Tor ref: 500 cells)
const STREAM_SENDME_WINDOW: i32 = 500;
const STREAM_SENDME_INCREMENT: i32 = 50;

/// Circuit default windows (Tor ref: 1000 cells)
const CIRCUIT_SENDME_WINDOW: i32 = 1000;
const CIRCUIT_SENDME_INCREMENT: i32 = 100;

/// Max per-stream buffers
const MAX_SEND_BUFFER_SIZE: usize = 64 * 1024;
const MAX_RECV_BUFFER_SIZE: usize = 64 * 1024;

/// Scheduler
const DEFAULT_STREAM_QUANTUM_CELLS: i32 = 10;

/* ============================================================
Stream state
============================================================ */

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    NewResolve,  // Just created, waiting for RESOLVE
    NewConnect,  // Just created, waiting for BEGIN
    SentConnect, // BEGIN sent, waiting for CONNECTED
    SentResolve, // RESOLVE sent, waiting for RESOLVED
    Open,        // Stream is open and ready for data
    ExitWait,    // Waiting for exit node to close
    Closed,      // Stream is fully closed
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamEndReason {
    Misc = 1,
    ResolveFailed = 2,
    ConnectRefused = 3,
    ExitPolicy = 4,
    Destroy = 5,
    Done = 6,
    Timeout = 7,
    NoRoute = 8,
    Hibernating = 9,
    Internal = 10,
    ResourceLimit = 11,
    ConnReset = 12,
    TorProtocol = 13,
    NotDirectory = 14,
}

impl StreamEndReason {
    fn from_u8(v: u8) -> Self {
        match v {
            2 => StreamEndReason::ResolveFailed,
            3 => StreamEndReason::ConnectRefused,
            4 => StreamEndReason::ExitPolicy,
            5 => StreamEndReason::Destroy,
            6 => StreamEndReason::Done,
            7 => StreamEndReason::Timeout,
            8 => StreamEndReason::NoRoute,
            9 => StreamEndReason::Hibernating,
            10 => StreamEndReason::Internal,
            11 => StreamEndReason::ResourceLimit,
            12 => StreamEndReason::ConnReset,
            13 => StreamEndReason::TorProtocol,
            14 => StreamEndReason::NotDirectory,
            _ => StreamEndReason::Misc,
        }
    }
}

/// Supported application protocols over streams
#[derive(Debug, Clone)]
pub enum StreamProtocol {
    TCP,         // Raw TCP
    HTTP,        // HTTP/HTTPS
    DNS,         // DNS over Tor
    Directory,   // Tor directory
    ControlPort, // Tor control protocol
    Custom(String),
}

/// Per-stream object
#[derive(Debug)]
pub struct OnionStream {
    pub stream_id: StreamId,
    pub circuit_id: CircuitId,
    pub state: StreamState,
    pub target_host: String,
    pub target_port: u16,
    pub created_time: u64,
    pub last_activity: u64,

    // flow control (stream-level)
    pub send_window: i32,    // cells we can put on circuit for this stream
    pub recv_window: i32,    // cells we may receive before we must SENDME
    pub package_window: i32, // used to throttle packing DATA
    pub deliver_window: i32, // used to throttle delivering up to app

    // buffers
    pub send_buffer: Vec<u8>, // app->stream pending bytes
    pub recv_buffer: Vec<u8>, // stream->app accumulated bytes

    // statistics
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub cells_sent: AtomicU32,
    pub cells_received: AtomicU32,

    pub protocol: StreamProtocol,
    pub application_data: BTreeMap<String, Vec<u8>>,

    // scheduler credit
    pub deficit: i32,
}

impl OnionStream {
    pub fn new(
        stream_id: StreamId,
        circuit_id: CircuitId,
        target: String,
        port: u16,
        protocol: StreamProtocol,
    ) -> Self {
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
    fn update_activity(&mut self) {
        self.last_activity = current_time_ms();
    }

    /// Application writes bytes to the stream (may buffer if windows are shut).
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), OnionError> {
        if self.state != StreamState::Open {
            return Err(OnionError::StreamClosed);
        }
        // Can we send cells now?
        if self.send_window <= 0 || self.package_window <= 0 {
            // buffer
            if self.send_buffer.len() + data.len() > MAX_SEND_BUFFER_SIZE {
                return Err(OnionError::NetworkError);
            }
            self.send_buffer.extend_from_slice(data);
            self.update_activity();
            return Ok(());
        }
        // try flush immediately
        self.flush_data(data)?;
        self.update_activity();
        Ok(())
    }

    /// App polls for received bytes (drains recv_buffer).
    pub fn recv_data(&mut self) -> Result<Vec<u8>, OnionError> {
        if self.recv_buffer.is_empty() {
            return Ok(Vec::new());
        }
        let out = core::mem::take(&mut self.recv_buffer);

        // Deliver count influences SENDME emission
        self.deliver_window -= num_cells_for_len(out.len());
        if self.deliver_window <= STREAM_SENDME_WINDOW - STREAM_SENDME_INCREMENT {
            // Ask peer to send more (stream-level SENDME)
            self.enqueue_sendme()?;
            self.deliver_window += STREAM_SENDME_INCREMENT;
        }
        self.update_activity();
        Ok(out)
    }

    /// Called when a RELAY_DATA payload arrives for this stream.
    pub fn handle_data_cell(&mut self, data: Vec<u8>) -> Result<(), OnionError> {
        if self.state != StreamState::Open {
            return Err(OnionError::StreamClosed);
        }
        if self.recv_window <= 0 {
            // flow control violation; drop or treat as error
            return Err(OnionError::NetworkError);
        }
        if self.recv_buffer.len() + data.len() > MAX_RECV_BUFFER_SIZE {
            return Err(OnionError::NetworkError);
        }

        self.recv_buffer.extend_from_slice(&data);
        self.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.cells_received.fetch_add(1, Ordering::Relaxed);
        self.recv_window -= 1;

        // If window low, emit SENDME preemptively (optional early)
        if self.recv_window <= STREAM_SENDME_WINDOW - STREAM_SENDME_INCREMENT {
            self.enqueue_sendme()?;
            self.recv_window += STREAM_SENDME_INCREMENT;
        }

        self.update_activity();
        Ok(())
    }

    /// CONNECTED from exit.
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

    /// RESOLVED (DNS).
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

    /// END (with reason).
    pub fn handle_end(&mut self, reason: StreamEndReason) -> Result<(), OnionError> {
        self.state = StreamState::Closed;
        self.application_data.insert("end_reason".into(), vec![reason as u8]);
        self.update_activity();
        Ok(())
    }

    /// Called when a SENDME for this stream is received (increments sending
    /// windows).
    pub fn handle_sendme(&mut self) {
        self.send_window += STREAM_SENDME_INCREMENT;
        self.package_window += STREAM_SENDME_INCREMENT;
        // scheduler credit
        self.deficit += DEFAULT_STREAM_QUANTUM_CELLS;
    }

    /// Internal: split and send data as RELAY_DATA cells.
    fn flush_data(&mut self, data: &[u8]) -> Result<(), OnionError> {
        if data.is_empty() {
            return Ok(());
        }

        // Enforce windows & scheduler deficit
        let mut remaining = data;
        while !remaining.is_empty()
            && self.send_window > 0
            && self.package_window > 0
            && self.deficit > 0
        {
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

        // If not fully sent, buffer the rest
        if !remaining.is_empty() {
            if self.send_buffer.len() + remaining.len() > MAX_SEND_BUFFER_SIZE {
                return Err(OnionError::NetworkError);
            }
            self.send_buffer.extend_from_slice(remaining);
        }

        Ok(())
    }

    /// Try to flush buffered data opportunistically (scheduler calls this).
    fn try_flush_buffered(&mut self) -> Result<bool, OnionError> {
        if self.send_buffer.is_empty()
            || self.send_window <= 0
            || self.package_window <= 0
            || self.deficit <= 0
        {
            return Ok(false);
        }

        let mut emitted_any = false;
        while !self.send_buffer.is_empty()
            && self.send_window > 0
            && self.package_window > 0
            && self.deficit > 0
        {
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

    /// Issue a SENDME for this stream.
    fn enqueue_sendme(&mut self) -> Result<(), OnionError> {
        // Prefer a proper SENDME cell if our `Cell` exposes it; fallback to DATA(0)
        #[cfg(feature = "relay_sendme_cell")]
        {
            let cell = Cell::relay_sendme_cell(self.circuit_id, self.stream_id);
            send_cell(cell)
        }
        #[cfg(not(feature = "relay_sendme_cell"))]
        {
            // Tor SENDME is a dedicated command; using empty DATA as a compatibility
            // fallback. Switch to the dedicated constructor if available.
            let cell = Cell::relay_data_cell(self.circuit_id, self.stream_id, Vec::new());
            send_cell(cell)
        }
    }
}

/* ============================================================
Metrics
============================================================ */

#[derive(Debug, Clone)]
pub struct StreamMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub cells_sent: u32,
    pub cells_received: u32,
    pub uptime_ms: u64,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub send_window: i32,
    pub recv_window: i32,
}

/* ============================================================
Stream Manager
============================================================ */

pub struct StreamManager {
    streams: Mutex<BTreeMap<StreamId, OnionStream>>,
    by_circuit: Mutex<BTreeMap<CircuitId, Vec<StreamId>>>,
    stream_id_counter: AtomicU16,
    stream_stats: StreamStatistics,
    flow: FlowControlManager,
    proto: ProtocolHandlerRegistry,
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

    /// Create a new CONNECT (BEGIN) stream over `circuit_id`.
    pub fn create_stream(
        &self,
        circuit_id: CircuitId,
        target: String,
        port: u16,
    ) -> Result<StreamId, OnionError> {
        let sid = self.next_stream_id();
        let proto = self.detect_protocol(&target, port);
        let mut s = OnionStream::new(sid, circuit_id, target.clone(), port, proto);

        // Send BEGIN
        let cell = Cell::relay_begin_cell(circuit_id, sid, target, port);
        send_cell(cell)?;

        s.state = StreamState::SentConnect;

        self.streams.lock().insert(sid, s);
        self.by_circuit.lock().entry(circuit_id).or_default().push(sid);

        self.stream_stats.active_streams.fetch_add(1, Ordering::Relaxed);
        self.stream_stats.total_streams_created.fetch_add(1, Ordering::Relaxed);
        Ok(sid)
    }

    /// Create a DNS RESOLVE stream.
    pub fn create_resolve_stream(
        &self,
        circuit_id: CircuitId,
        hostname: String,
    ) -> Result<StreamId, OnionError> {
        let sid = self.next_stream_id();
        let mut s = OnionStream::new_resolve(sid, circuit_id, hostname.clone());

        // Tor RESOLVE uses RELAY_RESOLVE command; if unavailable, send a RESOLVE
        // payload via DATA as fallback.
        let payload = {
            let mut p = hostname.into_bytes();
            p.push(0); // NUL-terminated per older clients; adjust if we have a dedicated RESOLVE cell
            p
        };

        // If we have Cell::relay_resolve_cell, prefer it; otherwise use DATA as
        // transport shim.
        #[cfg(feature = "relay_resolve_cell")]
        let cell = Cell::relay_resolve_cell(circuit_id, sid, payload);
        #[cfg(not(feature = "relay_resolve_cell"))]
        let cell = Cell::relay_data_cell(circuit_id, sid, payload);

        send_cell(cell)?;
        s.state = StreamState::SentResolve;

        self.streams.lock().insert(sid, s);
        self.by_circuit.lock().entry(circuit_id).or_default().push(sid);

        self.stream_stats.active_streams.fetch_add(1, Ordering::Relaxed);
        self.stream_stats.total_streams_created.fetch_add(1, Ordering::Relaxed);
        Ok(sid)
    }

    /// App wants to send user data over a stream.
    pub fn send_data(&self, stream_id: StreamId, data: &[u8]) -> Result<(), OnionError> {
        let mut map = self.streams.lock();
        let s = map.get_mut(&stream_id).ok_or(OnionError::StreamClosed)?;
        s.send_data(data)?;
        self.stream_stats.total_data_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// App polls for data from a stream.
    pub fn recv_data(&self, stream_id: StreamId) -> Result<Vec<u8>, OnionError> {
        let mut map = self.streams.lock();
        let s = map.get_mut(&stream_id).ok_or(OnionError::StreamClosed)?;
        let out = s.recv_data()?;
        if !out.is_empty() {
            self.stream_stats.total_data_transferred.fetch_add(out.len() as u64, Ordering::Relaxed);
        }
        Ok(out)
    }

    /// Circuit has delivered a relay cell: dispatch by command/stream_id.
    pub fn handle_relay_cell(
        &self,
        circuit_id: CircuitId,
        relay: RelayCell,
    ) -> Result<(), OnionError> {
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
                    // CONNECTED payload: [ip(4)][ttl(4)] or empty
                    if relay.payload.len() >= 8 {
                        let addr = [
                            relay.payload[0],
                            relay.payload[1],
                            relay.payload[2],
                            relay.payload[3],
                        ];
                        let ttl = u32::from_be_bytes([
                            relay.payload[4],
                            relay.payload[5],
                            relay.payload[6],
                            relay.payload[7],
                        ]);
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
                    // Very simplified: payload may carry multiple A records concatenated (4 bytes
                    // each) + optional TTL
                    let mut addrs = Vec::new();
                    for chunk in relay.payload.chunks_exact(4) {
                        addrs.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    }
                    s.handle_resolved(addrs, 60)?; // default TTL if not present
                }
            }
            RelayCommand::RelayEnd => {
                let sid = relay.header.stream_id;
                let mut map = self.streams.lock();
                if let Some(s) = map.get_mut(&sid) {
                    let reason = relay.payload.get(0).copied().unwrap_or(0);
                    s.handle_end(StreamEndReason::from_u8(reason))?;
                    // cleanup if fully closed
                    if s.is_closed() {
                        map.remove(&sid);
                        self.remove_from_circuit(circuit_id, sid);
                        self.stream_stats.active_streams.fetch_sub(1, Ordering::Relaxed);
                        self.stream_stats.total_streams_closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            RelayCommand::RelaySendme => {
                // stream-level or circuit-level SENDME (stream_id==0 => circuit)
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
            // Other relay commands ignored here or handled elsewhere (BEGIN, EXTEND, etc.)
            _ => {}
        }
        Ok(())
    }

    /// Close a stream gracefully (sends END).
    pub fn close_stream(
        &self,
        stream_id: StreamId,
        reason: StreamEndReason,
    ) -> Result<(), OnionError> {
        let mut map = self.streams.lock();
        if let Some(s) = map.get_mut(&stream_id) {
            if s.state == StreamState::Closed {
                return Ok(());
            }
            let cell = Cell::relay_end_cell(s.circuit_id, s.stream_id, reason as u8);
            send_cell(cell)?;
            s.state = StreamState::ExitWait;
        }
        Ok(())
    }

    /// On timer / tick: run scheduler to flush buffered data subject to windows
    /// & congestion.
    pub fn tick(&self, circuit_id: CircuitId) {
        // Refill per-stream deficit (quantum)
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

        // flush buffered in round-robin order
        if let Some(ids) = self.by_circuit.lock().get(&circuit_id).cloned() {
            let mut map = self.streams.lock();
            for sid in ids {
                if let Some(s) = map.get_mut(&sid) {
                    // obey circuit window as well
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

        // Congestion controller can update windows periodically
        self.flow.cc_tick(circuit_id);
    }

    /// Statistics and metrics
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
        self.streams.lock().iter().filter(|(_, s)| s.is_open()).map(|(k, _)| *k).collect()
    }

    pub fn get_statistics(&self) -> &StreamStatistics {
        &self.stream_stats
    }

    pub fn cleanup_closed_streams(&self) {
        let mut map = self.streams.lock();
        let mut to_remove = Vec::new();
        for (sid, s) in map.iter() {
            if s.is_closed() {
                to_remove.push(*sid);
            }
        }
        drop(map);

        if !to_remove.is_empty() {
            let mut map = self.streams.lock();
            for sid in to_remove {
                if let Some(s) = map.remove(&sid) {
                    self.remove_from_circuit(s.circuit_id, sid);
                    self.stream_stats.active_streams.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn handle_data(&mut self, stream_id: StreamId, data: &[u8]) -> Result<(), OnionError> {
        let mut streams = self.streams.lock();
        if let Some(stream) = streams.get_mut(&stream_id) {
            stream.recv_buffer.extend_from_slice(data);
            stream.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        } else {
            Err(OnionError::StreamNotFound)
        }
    }

    pub fn handle_begin(&mut self, _cell: super::cell::RelayCell) -> Result<(), OnionError> {
        Ok(())
    }

    pub fn handle_connected(&mut self, _cell: super::cell::RelayCell) -> Result<(), OnionError> {
        Ok(())
    }

    pub fn handle_end(&mut self, _cell: super::cell::RelayCell) -> Result<(), OnionError> {
        Ok(())
    }

    /* -------- internals -------- */

    fn detect_protocol(&self, target: &str, port: u16) -> StreamProtocol {
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

    fn next_stream_id(&self) -> StreamId {
        self.stream_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn remove_from_circuit(&self, circuit_id: CircuitId, sid: StreamId) {
        let mut idx = self.by_circuit.lock();
        if let Some(v) = idx.get_mut(&circuit_id) {
            if let Some(pos) = v.iter().position(|x| *x == sid) {
                v.swap_remove(pos);
            }
        }
    }
}

/* ============================================================
Flow control & congestion
============================================================ */

struct FlowControlManager {
    circuit_windows: Mutex<BTreeMap<CircuitId, CircuitWindow>>,
    congestion: CongestionControl,
}

#[derive(Debug, Clone)]
struct CircuitWindow {
    send_window: i32,
    recv_window: i32,
    package_window: i32,
    deliver_window: i32,
}

impl FlowControlManager {
    fn new() -> Self {
        Self { circuit_windows: Mutex::new(BTreeMap::new()), congestion: CongestionControl::new() }
    }

    fn cw_mut(&self, cid: CircuitId) -> &mut CircuitWindow {
        // SAFETY: we always insert before returning reference in same scope
        let mut map = self.circuit_windows.lock();
        if !map.contains_key(&cid) {
            map.insert(
                cid,
                CircuitWindow {
                    send_window: CIRCUIT_SENDME_WINDOW,
                    recv_window: CIRCUIT_SENDME_WINDOW,
                    package_window: CIRCUIT_SENDME_WINDOW,
                    deliver_window: CIRCUIT_SENDME_WINDOW,
                },
            );
        }
        // We can't return a &mut from a temporary; so we operate via closures
        // externally.
        drop(map);
        // Caller must re-lock (helper methods below do that)
        // This pattern avoids returning refs across lock boundaries.
        // See helper methods below.
        unreachable!()
    }

    fn ensure(&self, cid: CircuitId) {
        let mut map = self.circuit_windows.lock();
        map.entry(cid).or_insert(CircuitWindow {
            send_window: CIRCUIT_SENDME_WINDOW,
            recv_window: CIRCUIT_SENDME_WINDOW,
            package_window: CIRCUIT_SENDME_WINDOW,
            deliver_window: CIRCUIT_SENDME_WINDOW,
        });
    }

    fn can_package_on_circuit(&self, cid: CircuitId) -> bool {
        self.ensure(cid);
        let map = self.circuit_windows.lock();
        if let Some(w) = map.get(&cid) {
            w.send_window > 0 && w.package_window > 0
        } else {
            false
        }
    }

    fn on_circuit_pack(&self, cid: CircuitId, cells: i32) {
        let mut map = self.circuit_windows.lock();
        if let Some(w) = map.get_mut(&cid) {
            w.send_window -= cells;
            w.package_window -= cells;
        }
    }

    fn handle_circuit_sendme(&self, cid: CircuitId) {
        let mut map = self.circuit_windows.lock();
        if let Some(w) = map.get_mut(&cid) {
            w.send_window += CIRCUIT_SENDME_INCREMENT;
            w.package_window += CIRCUIT_SENDME_INCREMENT;
        }
        self.congestion.on_ack(cid);
    }

    fn cc_tick(&self, cid: CircuitId) {
        self.congestion.on_tick(cid);
    }
}

struct CongestionControl {
    algorithm: CongestionAlgorithm,
    measurements: Mutex<BTreeMap<CircuitId, CongestionMeasurement>>,
}

#[derive(Debug, Clone, Copy)]
enum CongestionAlgorithm {
    FixedWindow, // default Tor alike
    AIMD,        // additive increase, multiplicative decrease
    Vegas,       // RTT-based probing
}

#[derive(Debug, Clone)]
struct CongestionMeasurement {
    rtt_samples: Vec<u32>,
    bandwidth_cells_per_s: u64,
    loss_rate: f32,
    last_ts: u64,
}

impl CongestionControl {
    fn new() -> Self {
        Self {
            algorithm: CongestionAlgorithm::FixedWindow,
            measurements: Mutex::new(BTreeMap::new()),
        }
    }

    fn ensure(&self, cid: CircuitId) {
        let mut m = self.measurements.lock();
        m.entry(cid).or_insert(CongestionMeasurement {
            rtt_samples: Vec::new(),
            bandwidth_cells_per_s: 0,
            loss_rate: 0.0,
            last_ts: current_time_ms(),
        });
    }

    fn on_ack(&self, cid: CircuitId) {
        match self.algorithm {
            CongestionAlgorithm::FixedWindow => {}
            CongestionAlgorithm::AIMD => {
                // simplistic AIMD: on ack, could increase circuit package window gradually
                // (actual window tuning happens in FlowControlManager if we decide to link
                // them)
                let mut m = self.measurements.lock();
                if let Some(mm) = m.get_mut(&cid) {
                    mm.bandwidth_cells_per_s = mm.bandwidth_cells_per_s.saturating_add(1);
                }
            }
            CongestionAlgorithm::Vegas => {}
        }
    }

    fn on_tick(&self, cid: CircuitId) {
        self.ensure(cid);
        // In a full implementation, we derive target window from recent RTT/bw
        // samples.
    }
}

/* ============================================================
Protocol handlers (registry)
============================================================ */

struct ProtocolHandlerRegistry {
    handlers: Mutex<BTreeMap<String, Box<dyn ProtocolHandler>>>,
}

impl ProtocolHandlerRegistry {
    fn new() -> Self {
        let r = Self { handlers: Mutex::new(BTreeMap::new()) };
        // Can register defaults here (e.g., "http", "dns") if desired.
        r
    }

    #[allow(dead_code)]
    fn register<H: ProtocolHandler + 'static>(&self, name: &str, h: H) {
        self.handlers.lock().insert(name.into(), Box::new(h));
    }

    #[allow(dead_code)]
    fn get(&self, key: &str) -> Option<Box<dyn ProtocolHandler>> {
        self.handlers.lock().get(key).map(|h| h.box_clone())
    }
}

trait ProtocolHandler: Send + Sync {
    fn handle_data(&self, stream: &mut OnionStream, data: &[u8]) -> Result<Vec<u8>, OnionError>;
    fn handle_connect(&self, stream: &mut OnionStream) -> Result<(), OnionError>;
    fn handle_close(&self, stream: &mut OnionStream) -> Result<(), OnionError>;
    fn box_clone(&self) -> Box<dyn ProtocolHandler>;
}

impl<T> ProtocolHandler for T
where
    T: Send + Sync + Clone + 'static + ProtocolHandlerCore,
{
    fn handle_data(&self, s: &mut OnionStream, d: &[u8]) -> Result<Vec<u8>, OnionError> {
        self.on_data(s, d)
    }
    fn handle_connect(&self, s: &mut OnionStream) -> Result<(), OnionError> {
        self.on_connect(s)
    }
    fn handle_close(&self, s: &mut OnionStream) -> Result<(), OnionError> {
        self.on_close(s)
    }
    fn box_clone(&self) -> Box<dyn ProtocolHandler> {
        Box::new(self.clone())
    }
}

trait ProtocolHandlerCore {
    fn on_data(&self, stream: &mut OnionStream, data: &[u8]) -> Result<Vec<u8>, OnionError>;
    fn on_connect(&self, stream: &mut OnionStream) -> Result<(), OnionError>;
    fn on_close(&self, stream: &mut OnionStream) -> Result<(), OnionError>;
}

/* Example handler skeletons (no heavy logic by default) */

#[derive(Clone)]
struct HttpHandler;
impl ProtocolHandlerCore for HttpHandler {
    fn on_data(&self, _s: &mut OnionStream, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        Ok(data.to_vec())
    }
    fn on_connect(&self, _s: &mut OnionStream) -> Result<(), OnionError> {
        Ok(())
    }
    fn on_close(&self, _s: &mut OnionStream) -> Result<(), OnionError> {
        Ok(())
    }
}

#[derive(Clone)]
struct DnsHandler;
impl ProtocolHandlerCore for DnsHandler {
    fn on_data(&self, _s: &mut OnionStream, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        Ok(data.to_vec())
    }
    fn on_connect(&self, _s: &mut OnionStream) -> Result<(), OnionError> {
        Ok(())
    }
    fn on_close(&self, _s: &mut OnionStream) -> Result<(), OnionError> {
        Ok(())
    }
}

/* ============================================================
Stats
============================================================ */

#[derive(Debug, Default)]
pub struct StreamStatistics {
    pub active_streams: AtomicU32,
    pub total_streams_created: AtomicU64,
    pub total_streams_closed: AtomicU64,
    pub total_data_transferred: AtomicU64,
    pub stream_creation_rate: AtomicU32,
    pub average_stream_lifetime: AtomicU64,
}

/* ============================================================
Utilities
============================================================ */

fn current_time_ms() -> u64 {
    // Prefer kernel-wide timer if available
    #[cfg(feature = "arch_time_timer")]
    {
        crate::arch::x86_64::time::timer::get_timestamp_ms().unwrap_or(0)
    }
    #[cfg(not(feature = "arch_time_timer"))]
    {
        crate::time::timestamp_millis()
    }
}

#[inline]
fn num_cells_for_len(len: usize) -> i32 {
    ((len + RELAY_PAYLOAD_SIZE - 1) / RELAY_PAYLOAD_SIZE) as i32
}

fn send_cell(cell: Cell) -> Result<(), OnionError> {
    if let Some(net) = get_network_stack() {
        let packet = cell.serialize();
        // Actual path should push this into the circuit's first hop;
        // Here we rely on network stack providing an appropriate send method.
        // net.send_packet(packet)?;
        // If expose a generic TCP writer for Tor links, we will call it here.
        let _ = packet;
    }
    Ok(())
}
