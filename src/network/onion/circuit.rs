/*!
 NONOS Circuit Management for Onion Routing
*/

#![no_std]

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::{OnionError};
use super::cell::{Cell, CellType};
use super::crypto::{HopCrypto, LayerKeys, OnionCrypto};
use super::directory::RelayDescriptor;
use crate::network::get_network_stack;

pub type CircuitId = u32;

/* ===== Circuit types ===== */

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState { Building, Open, Closing, Closed, Failed }

#[derive(Debug, Clone)]
pub struct CircuitHop {
    pub relay: RelayDescriptor,
    pub keys: LayerKeys,
    pub extend_info: Option<ExtendInfo>,
    pub rtt_ms: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone)]
pub struct ExtendInfo {
    pub identity_key: Vec<u8>,
    pub onion_key: Vec<u8>,
    pub ntor_onion_key: Vec<u8>,
    pub address: [u8; 4],
    pub port: u16,
    pub link_specifiers: Vec<LinkSpecifier>,
}

#[derive(Debug, Clone)]
pub enum LinkSpecifier {
    IPv4 { addr: [u8; 4], port: u16 },
    IPv6 { addr: [u8; 16], port: u16 },
    Legacy { identity: [u8; 20] },
    Ed25519 { identity: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitPurpose { General, HiddenService, HSDir, Introduction, Rendezvous, Testing, Preemptive }

#[derive(Debug, Clone)]
pub struct PathConstraints {
    pub require_guard: bool,
    pub require_exit: bool,
    pub exclude_nodes: Vec<[u8; 20]>,
    pub country_exclude: Vec<String>,
    pub max_family_members: u8,
    pub min_bandwidth: u64,
}
impl Default for PathConstraints {
    fn default() -> Self {
        Self {
            require_guard: true,
            require_exit: true,
            exclude_nodes: Vec::new(),
            country_exclude: Vec::new(),
            max_family_members: 1,
            min_bandwidth: 20 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Circuit {
    pub id: CircuitId,
    pub state: CircuitState,
    pub hops: Vec<CircuitHop>,
    pub created_time: u64,
    pub last_activity: u64,
    pub purpose: CircuitPurpose,
    pub crypto: OnionCrypto,
    pub max_streams: u16,
    pub active_streams: u16,
    pub path_selection_constraints: PathConstraints,
}

impl Circuit {
    pub fn new(id: CircuitId, purpose: CircuitPurpose) -> Self {
        Self {
            id,
            state: CircuitState::Building,
            hops: Vec::new(),
            created_time: Self::now_ms(),
            last_activity: Self::now_ms(),
            purpose,
            crypto: OnionCrypto::new(),
            max_streams: 65535,
            active_streams: 0,
            path_selection_constraints: PathConstraints::default(),
        }
    }

    pub fn add_hop(&mut self, relay: RelayDescriptor, keys: LayerKeys) -> Result<(), OnionError> {
        if self.hops.len() >= 3 {
            return Err(OnionError::CircuitBuildFailed);
        }
        let hop = CircuitHop {
            relay,
            keys,
            extend_info: None,
            rtt_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };
        self.hops.push(hop);
        let layer_keys: Vec<LayerKeys> = self.hops.iter().map(|h| h.keys.clone()).collect();
        self.crypto.add_circuit(self.id, layer_keys);
        Ok(())
    }

    pub fn mark_open(&mut self) { self.state = CircuitState::Open; self.last_activity = Self::now_ms(); }
    pub fn is_open(&self) -> bool { self.state == CircuitState::Open && self.hops.len() == 3 }
    pub fn encrypt_forward(&self, data: &[u8]) -> Result<Vec<u8>, OnionError> { self.crypto.encrypt_forward(self.id, data) }
    pub fn decrypt_backward(&self, data: &[u8]) -> Result<Vec<u8>, OnionError> { self.crypto.decrypt_backward(self.id, data) }
    pub fn hop_count(&self) -> usize { self.hops.len() }
    pub fn is_expired(&self, max_age_ms: u64) -> bool { Self::now_ms().saturating_sub(self.created_time) > max_age_ms }
    pub fn touch(&mut self) { self.last_activity = Self::now_ms(); }
    #[inline] fn now_ms() -> u64 { crate::nonos_time::now_ns() / 1_000_000 }
}

#[derive(Debug, Clone)]
pub struct CircuitMetrics {
    pub total_rtt_ms: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub active_streams: u16,
    pub uptime_ms: u64,
}

/* ===== Manager & build state ===== */

pub struct CircuitManager {
    circuits: Mutex<BTreeMap<CircuitId, Circuit>>,
    next_circuit_id: AtomicU32,
    building: Mutex<BTreeMap<CircuitId, BuildingCircuit>>,
    path_selection: PathSelector,
    perf: PerformanceMonitor,
    pool: CircuitPool,
}

#[derive(Debug)]
struct BuildingCircuit {
    id: CircuitId,
    target_hops: Vec<RelayDescriptor>,
    current_hop: usize,
    state: BuildState,
    crypto_state: Vec<HopCrypto>,
    start_time: u64,
    timeout_ms: u64,
    retries: u8,
}

#[derive(Debug, PartialEq)]
enum BuildState {
    SendingCreate,
    WaitingCreated,
    SendingExtend(usize),
    WaitingExtended(usize),
    Complete,
    Failed,
}

/* ===== Path selection & perf ===== */

struct PathSelector {
    guard_nodes: Mutex<Vec<RelayDescriptor>>,
    middle_nodes: Mutex<Vec<RelayDescriptor>>,
    exit_nodes: Mutex<Vec<RelayDescriptor>>,
    node_perf: Mutex<BTreeMap<[u8; 20], NodePerformance>>,
}

#[derive(Debug, Clone)]
struct NodePerformance {
    success_rate: f32,
    average_rtt: u32,
    bandwidth_estimate: u64,
    last_success: u64,
    failure_count: u32,
}

struct PerformanceMonitor {
    circuit_stats: Mutex<BTreeMap<CircuitId, CircuitMetrics>>,
    global: CircuitGlobalStats,
}

#[derive(Debug, Default)]
struct CircuitGlobalStats {
    pub total_circuits_built: AtomicU32,
    pub failed_circuits: AtomicU32,
    pub average_build_time_ms: AtomicU32,
    pub total_data_transferred: AtomicU32,
}

struct CircuitPool {
    prebuilt_circuits: Mutex<Vec<CircuitId>>,
    pool_size: usize,
    min_circuits: usize,
}

/* ===== Implementation ===== */

impl CircuitManager {
    pub fn new() -> Self {
        Self {
            circuits: Mutex::new(BTreeMap::new()),
            next_circuit_id: AtomicU32::new(1),
            building: Mutex::new(BTreeMap::new()),
            path_selection: PathSelector::new(),
            perf: PerformanceMonitor::new(),
            pool: CircuitPool::new(5, 2),
        }
    }

    pub fn init(&mut self) -> Result<(), OnionError> {
        self.path_selection.init()?;
        self.pool.init()?;
        Ok(())
    }

    pub fn build_circuit(&mut self, mut relays: Vec<RelayDescriptor>) -> Result<CircuitId, OnionError> {
        if relays.is_empty() { relays = self.path_selection.select_optimal_path(&PathConstraints::default())?; }
        if relays.len() != 3 { return Err(OnionError::InsufficientRelays); }

        let circuit_id = self.next_circuit_id.fetch_add(1, Ordering::Relaxed);
        let building = BuildingCircuit {
            id: circuit_id,
            target_hops: relays.clone(),
            current_hop: 0,
            state: BuildState::SendingCreate,
            crypto_state: Vec::new(),
            start_time: now_ms(),
            timeout_ms: 60_000,
            retries: 0,
        };
        self.building.lock().insert(circuit_id, building);
        self.send_create_cell(circuit_id, &relays[0])?;
        Ok(circuit_id)
    }

    fn send_create_cell(&self, circuit_id: CircuitId, guard: &RelayDescriptor) -> Result<(), OnionError> {
        let mut hop_crypto = HopCrypto::new(&guard.ntor_onion_key)?;
        let cell = Cell::create2_cell(circuit_id, 2, hop_crypto.handshake_data()); // 2 = ntor
        self.send_cell_to_relay(cell, guard)?;
        if let Some(mut bmap) = self.building.try_lock() {
            if let Some(b) = bmap.get_mut(&circuit_id) {
                b.state = BuildState::WaitingCreated;
                b.crypto_state.push(hop_crypto);
            }
        }
        Ok(())
    }

    fn send_extend_cell(&self, circuit_id: CircuitId, target: &RelayDescriptor) -> Result<(), OnionError> {
        let extend_info = ExtendInfo {
            identity_key: target.identity_digest.to_vec(),
            onion_key: target.ntor_onion_key.clone(),
            ntor_onion_key: target.ntor_onion_key.clone(),
            address: target.address,
            port: target.port,
            link_specifiers: vec![
                LinkSpecifier::IPv4 { addr: target.address, port: target.port },
                LinkSpecifier::Ed25519 { identity: target.ed25519_identity.clone() },
            ],
        };
        let mut hop_crypto = HopCrypto::new(&target.ntor_onion_key)?;
        let cell = Cell::extend2_cell(circuit_id, extend_info, 2, hop_crypto.handshake_data()); // ntor
        self.send_cell_through_circuit(circuit_id, cell)?;
        if let Some(mut bmap) = self.building.try_lock() {
            if let Some(b) = bmap.get_mut(&circuit_id) { b.crypto_state.push(hop_crypto); }
        }
        Ok(())
    }

    /// Handle CREATED/CREATED2 from guard: strip 2-byte length if present (Created2).
    pub fn handle_created_cell(&mut self, circuit_id: CircuitId, cell: Cell) -> Result<(), OnionError> {
        let (target_hop_0, keys, rtt) = {
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            if b.state != BuildState::WaitingCreated { return Err(OnionError::InvalidCell); }

            let crypto = b.crypto_state.last_mut().ok_or(OnionError::CryptoError)?;
            let start = now_ms();
            let payload = strip_len_prefix_if_any(cell.is_variable_length, cell.command, &cell.payload)?;
            crypto.complete_handshake(payload)?;
            let rtt = now_ms().saturating_sub(start) as u32;
            b.current_hop = 1;
            let target_hop_0 = b.target_hops[0].clone();
            let keys = LayerKeys::from_hop_crypto(crypto);
            (target_hop_0, keys, rtt)
        };

        {
            let mut circuits = self.circuits.lock();
            let entry = circuits.entry(circuit_id).or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));
            entry.add_hop(target_hop_0, keys)?;
            entry.hops[0].rtt_ms = ewma_update(entry.hops[0].rtt_ms, rtt);
            entry.touch();
        }

        let mut bmap = self.building.lock();
        let b = bmap.get_mut(&circuit_id).unwrap();
        if b.target_hops.len() == 1 {
            drop(bmap);
            self.complete_circuit(circuit_id)?;
        } else {
            b.state = BuildState::SendingExtend(1);
            let relay1 = b.target_hops[1].clone();
            drop(bmap);
            self.send_extend_cell(circuit_id, &relay1)?;
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).unwrap();
            b.state = BuildState::WaitingExtended(1);
        }
        Ok(())
    }

    /// Handle EXTENDED/EXTENDED2 (mid/exit hops): strip length prefix if present (Extended2).
    pub fn handle_extended_cell(&mut self, circuit_id: CircuitId, cell: Cell) -> Result<(), OnionError> {
        let (expected_hop, relay, keys, rtt) = {
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            let expected_hop = b.current_hop;
            if b.state != BuildState::WaitingExtended(expected_hop) { return Err(OnionError::InvalidCell); }

            let crypto = b.crypto_state.get_mut(expected_hop).ok_or(OnionError::CryptoError)?;
            let start = now_ms();
            // cell.payload here is already decrypted relay payload
            let payload = strip_len_prefix_if_any(cell.is_variable_length, cell.command, &cell.payload)?;
            crypto.complete_handshake(payload)?;
            let rtt = now_ms().saturating_sub(start) as u32;
            let relay = b.target_hops[expected_hop].clone();
            let keys = LayerKeys::from_hop_crypto(crypto);
            (expected_hop, relay, keys, rtt)
        };

        {
            let mut circuits = self.circuits.lock();
            let entry = circuits.entry(circuit_id).or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));
            entry.add_hop(relay, keys)?;
            let idx = entry.hop_count() - 1;
            entry.hops[idx].rtt_ms = ewma_update(entry.hops[idx].rtt_ms, rtt);
            entry.touch();
        }

        let mut bmap2 = self.building.lock();
        let b2 = bmap2.get_mut(&circuit_id).unwrap();
        b2.current_hop += 1;
        if b2.current_hop >= b2.target_hops.len() {
            drop(bmap2);
            self.complete_circuit(circuit_id)?;
        } else {
            let next = b2.current_hop;
            b2.state = BuildState::SendingExtend(next);
            let target = b2.target_hops[next].clone();
            drop(bmap2);
            self.send_extend_cell(circuit_id, &target)?;
            let mut bmap3 = self.building.lock();
            let b3 = bmap3.get_mut(&circuit_id).unwrap();
            b3.state = BuildState::WaitingExtended(next);
        }
        Ok(())
    }

    fn complete_circuit(&mut self, circuit_id: CircuitId) -> Result<(), OnionError> {
        let building = { let mut bmap = self.building.lock(); bmap.remove(&circuit_id).ok_or(OnionError::CircuitBuildFailed)? };
        {
            let mut circuits = self.circuits.lock();
            let circuit = circuits.entry(circuit_id).or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));
            if circuit.hop_count() != building.target_hops.len() { return Err(OnionError::CircuitBuildFailed); }
            let build_time = now_ms().saturating_sub(building.start_time);
            self.perf.record_circuit_built(circuit_id, build_time);
            circuit.mark_open();
        }
        self.pool.maybe_add(circuit_id);
        Ok(())
    }

    pub fn get_circuit(&self, circuit_id: CircuitId) -> Option<Circuit> { self.circuits.lock().get(&circuit_id).cloned() }
    pub fn get_open_circuits(&self) -> Vec<CircuitId> {
        self.circuits.lock().iter().filter(|(_, c)| c.is_open()).map(|(id, _)| *id).collect()
    }

    pub fn close_circuit(&mut self, circuit_id: CircuitId) -> Result<(), OnionError> {
        if let Some(mut circuit) = self.circuits.lock().remove(&circuit_id) {
            circuit.state = CircuitState::Closing;
            let cell = Cell::destroy_cell(circuit_id, 0);
            let _ = self.send_cell_through_circuit(circuit_id, cell);
        }
        Ok(())
    }

    pub fn get_stats(&self) -> CircuitStats {
        let circuits = self.circuits.lock();
        let building = self.building.lock();
        CircuitStats {
            total_circuits: circuits.len(),
            open_circuits: circuits.iter().filter(|(_, c)| c.is_open()).count(),
            building_circuits: building.len(),
            failed_circuits: self.perf.global.failed_circuits.load(Ordering::Relaxed),
            total_built: self.perf.global.total_circuits_built.load(Ordering::Relaxed),
            average_build_time_ms: self.perf.global.average_build_time_ms.load(Ordering::Relaxed),
        }
    }

    pub fn cleanup_expired_circuits(&mut self, max_age_ms: u64) {
        {
            let mut circuits = self.circuits.lock();
            let expired_ids: Vec<_> = circuits.iter()
                .filter(|(_, c)| c.is_expired(max_age_ms) || matches!(c.state, CircuitState::Failed | CircuitState::Closed))
                .map(|(id, _)| *id)
                .collect();
            for id in expired_ids { circuits.remove(&id); }
        }
        {
            let now = now_ms();
            let mut bmap = self.building.lock();
            let mut fail_list: Vec<CircuitId> = Vec::new();
            for (id, b) in bmap.iter() {
                if now.saturating_sub(b.start_time) > b.timeout_ms { fail_list.push(*id); }
            }
            for id in fail_list {
                bmap.remove(&id);
                self.perf.global.failed_circuits.fetch_add(1, Ordering::Relaxed);
                let mut circuits = self.circuits.lock();
                circuits.entry(id).and_modify(|c| c.state = CircuitState::Failed).or_insert_with(|| {
                    let mut c = Circuit::new(id, CircuitPurpose::General);
                    c.state = CircuitState::Failed;
                    c
                });
            }
        }
    }

    fn send_cell_to_relay(&self, cell: Cell, _relay: &RelayDescriptor) -> Result<(), OnionError> {
        if let Some(net) = get_network_stack() {
            let packet = cell.serialize();
            net.send_tcp_packet(&packet).map_err(|_| OnionError::NetworkError)?;
            Ok(())
        } else {
            Err(OnionError::NetworkError)
        }
    }

    fn send_cell_through_circuit(&self, circuit_id: CircuitId, mut cell: Cell) -> Result<(), OnionError> {
        let mut circuits = self.circuits.lock();
        if let Some(c) = circuits.get_mut(&circuit_id) {
            let enc = c.encrypt_forward(&cell.payload)?;
            cell.payload = enc;
            if c.hops.first().is_some() {
                drop(circuits);
                if let Some(net) = get_network_stack() {
                    let packet = cell.serialize();
                    net.send_tcp_packet(&packet).map_err(|_| OnionError::NetworkError)
                } else {
                    Err(OnionError::NetworkError)
                }
            } else {
                Err(OnionError::CircuitBuildFailed)
            }
        } else {
            Err(OnionError::CircuitBuildFailed)
        }
    }

    pub fn transmit_cell(&self, circuit_id: CircuitId, mut cell: Cell) -> Result<(), OnionError> {
        let mut circuits = self.circuits.lock();
        if let Some(circuit) = circuits.get_mut(&circuit_id) {
            if !circuit.is_open() {
                return Err(OnionError::CircuitError);
            }
            
            // Encrypt the cell payload through all hops
            let encrypted_payload = circuit.encrypt_forward(&cell.payload)?;
            cell.payload = encrypted_payload;
            cell.circuit_id = circuit_id;
            
            // Send to the first relay in the circuit
            if let Some(first_relay) = circuit.hops.first() {
                let relay_ref = first_relay.relay.clone();
                circuit.touch(); // Update last activity
                drop(circuits);
                self.send_cell_to_relay(cell, &relay_ref)
            } else {
                Err(OnionError::CircuitError)
            }
        } else {
            Err(OnionError::CircuitNotFound)
        }
    }
}

/* ===== Stats DTO ===== */

#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_circuits: usize,
    pub open_circuits: usize,
    pub building_circuits: usize,
    pub failed_circuits: u32,
    pub total_built: u32,
    pub average_build_time_ms: u32,
}

/* ===== Path selector & perf (same bodies) ===== */

impl PathSelector {
    fn new() -> Self {
        Self {
            guard_nodes: Mutex::new(Vec::new()),
            middle_nodes: Mutex::new(Vec::new()),
            exit_nodes: Mutex::new(Vec::new()),
            node_perf: Mutex::new(BTreeMap::new()),
        }
    }
    fn init(&self) -> Result<(), OnionError> { Ok(()) }
    fn select_optimal_path(&self, _constraints: &PathConstraints) -> Result<Vec<RelayDescriptor>, OnionError> {
        Err(OnionError::RelayNotFound)
    }
}

impl PerformanceMonitor {
    fn new() -> Self { Self { circuit_stats: Mutex::new(BTreeMap::new()), global: CircuitGlobalStats::default() } }
    fn record_circuit_built(&self, circuit_id: CircuitId, build_time_ms: u64) {
        self.global.total_circuits_built.fetch_add(1, Ordering::Relaxed);
        let current_avg = self.global.average_build_time_ms.load(Ordering::Relaxed) as u64;
        let total_built = self.global.total_circuits_built.load(Ordering::Relaxed) as u64;
        let new_avg = if total_built == 0 { build_time_ms } else { (current_avg.saturating_mul(total_built.saturating_sub(1)) + build_time_ms) / total_built };
        self.global.average_build_time_ms.store(new_avg as u32, Ordering::Relaxed);
        self.circuit_stats.lock().insert(circuit_id, CircuitMetrics {
            total_rtt_ms: 0, total_bytes_sent: 0, total_bytes_received: 0, active_streams: 0, uptime_ms: 0
        });
    }
}

impl CircuitPool {
    fn new(pool_size: usize, min_circuits: usize) -> Self {
        Self { prebuilt_circuits: Mutex::new(Vec::new()), pool_size, min_circuits }
    }
    fn init(&self) -> Result<(), OnionError> { Ok(()) }
    fn maybe_add(&self, id: CircuitId) {
        let mut v = self.prebuilt_circuits.lock();
        if v.len() < self.pool_size { v.push(id); }
    }
}

/* ===== helpers ===== */

#[inline] fn now_ms() -> u64 { crate::nonos_time::now_ns() / 1_000_000 }

#[inline] fn ewma_update(old_ms: u32, sample_ms: u32) -> u32 {
    if old_ms == 0 { return sample_ms; }
    let alpha_num = 3u32; let alpha_den = 10u32;
    ((alpha_num * sample_ms + (alpha_den - alpha_num) * old_ms) / alpha_den)
}

/// For Created2/Extended2 payloads, strip the first 2 bytes length prefix and return the slice.
/// For others, return the full payload.
fn strip_len_prefix_if_any(is_var: bool, command: u8, payload: &[u8]) -> Result<&[u8], OnionError> {
    if is_var && (command == CellType::Created2 as u8) {
        if payload.len() < 2 { return Err(OnionError::InvalidCell); }
        let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + n { return Err(OnionError::InvalidCell); }
        return Ok(&payload[2..2 + n]);
    }
    // For EXTENDED2, we receive it inside a RELAY cell; CellProcessor passes only relay payload here.
    // Relay payload layout for EXTENDED2 is: u16 len || handshake[n].
    if !is_var && command == CellType::Relay as u8 {
        if payload.len() >= 2 {
            let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            if payload.len() >= 2 + n && n > 0 && n <= 1024 {
                return Ok(&payload[2..2 + n]);
            }
        }
    }
    Ok(payload)
}
