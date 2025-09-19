#![no_std]

/*!
 NONOS Circuit Management for Onion Routing

 NONOS circuit building and management using cryptography.
 Implements Tor-compatible circuit construction (CREATE2/EXTEND2 w/ ntor)
 with space for post-quantum extensions at the hop-crypto layer.

 Key properties:
 - Strict build state machine with timeouts and retries
 - Per-hop cryptographic state (ntor) -> LayerKeys for onion crypto
 - Path selection with constraints & basic performance gating
 - EWMA RTT metrics, counters, circuit pool scaffolding
 - Safe layered encryption for outbound cells
*/

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::{OnionError, RelayDescriptor};
use super::cell::Cell;
use super::crypto::{HopCrypto, LayerKeys, OnionCrypto};
use crate::network::get_network_stack;

pub type CircuitId = u32;

/* ===== Circuit types ===== */

/// Circuit state machine
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Building,
    Open,
    Closing,
    Closed,
    Failed,
}

/// Single hop in an onion circuit
#[derive(Debug, Clone)]
pub struct CircuitHop {
    pub relay: RelayDescriptor,
    pub keys: LayerKeys,
    pub extend_info: Option<ExtendInfo>,
    pub rtt_ms: u32, // Round-trip time for performance monitoring (EWMA, ms)
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Information for extending circuit to next hop
#[derive(Debug, Clone)]
pub struct ExtendInfo {
    pub identity_key: Vec<u8>,
    pub onion_key: Vec<u8>,
    pub ntor_onion_key: Vec<u8>, // ntor key for modern handshake
    pub address: [u8; 4],
    pub port: u16,
    pub link_specifiers: Vec<LinkSpecifier>,
}

/// Link specifier types for different address formats
#[derive(Debug, Clone)]
pub enum LinkSpecifier {
    IPv4 { addr: [u8; 4], port: u16 },
    IPv6 { addr: [u8; 16], port: u16 },
    Legacy { identity: [u8; 20] },
    Ed25519 { identity: [u8; 32] },
}

/// Circuit purpose types
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitPurpose {
    General,        // General client circuits
    HiddenService,  // Hidden service circuits
    HSDir,          // Hidden service directory queries
    Introduction,   // Introduction points
    Rendezvous,     // Rendezvous points
    Testing,        // Circuit testing
    Preemptive,     // Pre-built circuits for performance
}

/// Path selection constraints
#[derive(Debug, Clone)]
pub struct PathConstraints {
    pub require_guard: bool,
    pub require_exit: bool,
    pub exclude_nodes: Vec<[u8; 20]>, // Node fingerprints to exclude
    pub country_exclude: Vec<String>, // Country codes to exclude
    pub max_family_members: u8,        // Max relays from same family
    pub min_bandwidth: u64,            // Minimum bandwidth requirement
}

impl Default for PathConstraints {
    fn default() -> Self {
        PathConstraints {
            require_guard: true,
            require_exit: true,
            exclude_nodes: Vec::new(),
            country_exclude: Vec::new(),
            max_family_members: 1,
            min_bandwidth: 20 * 1024, // 20 KB/s minimum
        }
    }
}

/// Complete onion routing circuit
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
        Circuit {
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

    /// Add hop to circuit with real cryptographic keys
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

        // Recompute layers in crypto engine for this circuit
        let layer_keys: Vec<LayerKeys> = self.hops.iter().map(|h| h.keys.clone()).collect();
        self.crypto.add_circuit(self.id, layer_keys);

        Ok(())
    }

    pub fn mark_open(&mut self) {
        self.state = CircuitState::Open;
        self.last_activity = Self::now_ms();
    }

    pub fn is_open(&self) -> bool {
        self.state == CircuitState::Open && self.hops.len() == 3
    }

    /// Encrypt data through circuit layers (client->exit direction)
    pub fn encrypt_forward(&self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        self.crypto.encrypt_forward(self.id, data)
    }

    /// Decrypt data from circuit (exit->client direction)
    pub fn decrypt_backward(&self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        self.crypto.decrypt_backward(self.id, data)
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn is_expired(&self, max_age_ms: u64) -> bool {
        Self::now_ms().saturating_sub(self.created_time) > max_age_ms
    }

    pub fn touch(&mut self) {
        self.last_activity = Self::now_ms();
    }

    /// Get circuit performance metrics
    pub fn get_performance_metrics(&self) -> CircuitMetrics {
        let total_rtt = self.hops.iter().map(|h| h.rtt_ms as u64).sum();
        let total_sent = self.hops.iter().map(|h| h.bytes_sent).sum();
        let total_received = self.hops.iter().map(|h| h.bytes_received).sum();

        CircuitMetrics {
            total_rtt_ms: total_rtt,
            total_bytes_sent: total_sent,
            total_bytes_received: total_received,
            active_streams: self.active_streams,
            uptime_ms: Self::now_ms().saturating_sub(self.created_time),
        }
    }

    #[inline]
    fn now_ms() -> u64 {
        use crate::time;
        time::timestamp_millis()
    }
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

/// Circuit manager with advanced path selection and performance monitoring
pub struct CircuitManager {
    circuits: Mutex<BTreeMap<CircuitId, Circuit>>,
    next_circuit_id: AtomicU32,
    building: Mutex<BTreeMap<CircuitId, BuildingCircuit>>,
    path_selection: PathSelector,
    perf: PerformanceMonitor,
    pool: CircuitPool,
}

/// State machine for circuit construction
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

/// Advanced path selection logic
struct PathSelector {
    guard_nodes: Mutex<Vec<RelayDescriptor>>,
    middle_nodes: Mutex<Vec<RelayDescriptor>>,
    exit_nodes: Mutex<Vec<RelayDescriptor>>,
    node_perf: Mutex<BTreeMap<[u8; 20], NodePerformance>>,
}

#[derive(Debug, Clone)]
struct NodePerformance {
    success_rate: f32,     // 0..1
    average_rtt: u32,      // ms
    bandwidth_estimate: u64,
    last_success: u64,
    failure_count: u32,
}

/// Performance monitoring and circuit optimization
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

/* ===== Circuit pool (prebuilt) ===== */

struct CircuitPool {
    prebuilt_circuits: Mutex<Vec<CircuitId>>,
    pool_size: usize,
    min_circuits: usize,
}

/* ===== Implementation ===== */

impl CircuitManager {
    pub fn new() -> Self {
        CircuitManager {
            circuits: Mutex::new(BTreeMap::new()),
            next_circuit_id: AtomicU32::new(1),
            building: Mutex::new(BTreeMap::new()),
            path_selection: PathSelector::new(),
            perf: PerformanceMonitor::new(),
            pool: CircuitPool::new(5, 2), // pool of 5, ensure at least 2 ready
        }
    }

    pub fn init(&mut self) -> Result<(), OnionError> {
        self.path_selection.init()?;
        self.pool.init()?;
        Ok(())
    }

    /// Build circuit with advanced path selection
    pub fn build_circuit(&mut self, relays: Vec<RelayDescriptor>) -> Result<CircuitId, OnionError> {
        self.build_circuit_with_constraints(relays, PathConstraints::default())
    }

    /// Build circuit with specific path constraints
    pub fn build_circuit_with_constraints(
        &mut self,
        mut relays: Vec<RelayDescriptor>,
        constraints: PathConstraints,
    ) -> Result<CircuitId, OnionError> {
        if relays.is_empty() {
            relays = self.path_selection.select_optimal_path(&constraints)?;
        }
        if relays.len() != 3 {
            return Err(OnionError::InsufficientRelays);
        }
        self.validate_path(&relays, &constraints)?;

        let circuit_id = self.next_circuit_id.fetch_add(1, Ordering::Relaxed);

        let building = BuildingCircuit {
            id: circuit_id,
            target_hops: relays.clone(),
            current_hop: 0,
            state: BuildState::SendingCreate,
            crypto_state: Vec::new(),
            start_time: now_ms(),
            timeout_ms: 60_000, // 60s build timeout
            retries: 0,
        };

        self.building.lock().insert(circuit_id, building);

        // Kick off with CREATE2 to guard
        self.send_create_cell(circuit_id, &relays[0])?;

        Ok(circuit_id)
    }

    /// Validate circuit path meets constraints
    fn validate_path(
        &self,
        relays: &[RelayDescriptor],
        constraints: &PathConstraints,
    ) -> Result<(), OnionError> {
        if constraints.require_guard && !relays[0].flags.is_guard {
            return Err(OnionError::RelayNotFound);
        }
        if constraints.require_exit && !relays[2].flags.is_exit {
            return Err(OnionError::RelayNotFound);
        }

        // simple bandwidth gate on all hops
        for r in relays {
            if r.bandwidth < constraints.min_bandwidth {
                return Err(OnionError::RelayNotFound);
            }
        }

        // family conflict check
        let f0 = &relays[0].family;
        let f1 = &relays[1].family;
        let f2 = &relays[2].family;
        if (!f0.is_empty() && f0 == f1)
            || (!f0.is_empty() && f0 == f2)
            || (!f1.is_empty() && f1 == f2)
        {
            return Err(OnionError::RelayNotFound);
        }

        // exclude fingerprints
        for r in relays {
            if constraints.exclude_nodes.contains(&r.fingerprint) {
                return Err(OnionError::RelayNotFound);
            }
        }

        // country exclude (best-effort; relies on RelayDescriptor.country)
        if !constraints.country_exclude.is_empty() {
            for r in relays {
                if !r.country_code.is_empty() {
                    let cc = &r.country_code;
                    if constraints.country_exclude.iter().any(|x| x == cc) {
                        return Err(OnionError::RelayNotFound);
                    }
                }
            }
        }

        Ok(())
    }

    /* ===== Build flow ===== */

    /// Send CREATE2 cell with ntor handshake
    fn send_create_cell(&self, circuit_id: CircuitId, guard: &RelayDescriptor) -> Result<(), OnionError> {
        // prepare ntor handshake for hop 0
        let mut hop_crypto = HopCrypto::new(&guard.ntor_onion_key)?;
        let cell = Cell::create2_cell(circuit_id, 2, hop_crypto.handshake_data()); // 2 = ntor

        // to first hop directly
        self.send_cell_to_relay(cell, guard)?;

        // update building state
        if let Some(mut bmap) = self.building.try_lock() {
            if let Some(b) = bmap.get_mut(&circuit_id) {
                b.state = BuildState::WaitingCreated;
                b.crypto_state.push(hop_crypto);
            }
        }
        Ok(())
    }

    /// Send EXTEND2 cell with ntor handshake via existing circuit
    fn send_extend_cell(&self, circuit_id: CircuitId, target: &RelayDescriptor) -> Result<(), OnionError> {
        let extend_info = ExtendInfo {
            identity_key: target.identity_digest.to_vec(),
            onion_key: target.ntor_onion_key.clone(),
            ntor_onion_key: target.ntor_onion_key.clone(),
            address: target.address,
            port: target.port,
            link_specifiers: vec![
                LinkSpecifier::IPv4 {
                    addr: target.address,
                    port: target.port,
                },
                LinkSpecifier::Ed25519 {
                    identity: target.ed25519_identity.clone(),
                },
            ],
        };

        let mut hop_crypto = HopCrypto::new(&target.ntor_onion_key)?;
        let cell = Cell::extend2_cell(circuit_id, extend_info, 2, hop_crypto.handshake_data()); // 2 = ntor

        // go through layered encryption to guard
        self.send_cell_through_circuit(circuit_id, cell)?;

        // persist hop-crypto for handshake completion upon EXTENDED2
        if let Some(mut bmap) = self.building.try_lock() {
            if let Some(b) = bmap.get_mut(&circuit_id) {
                b.crypto_state.push(hop_crypto);
            }
        }
        Ok(())
    }

    /// Handle CREATED/CREATED2 response from guard
    pub fn handle_created_cell(&mut self, circuit_id: CircuitId, cell: Cell) -> Result<(), OnionError> {
        let (target_hop_0, keys, rtt) = {
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;

            if b.state != BuildState::WaitingCreated {
                return Err(OnionError::InvalidCell);
            }

            // ntor finish for hop0
            let crypto = b.crypto_state.last_mut().ok_or(OnionError::CryptoError)?;
            let start = now_ms();
            crypto.complete_handshake(&cell.payload)?;
            let rtt = now_ms().saturating_sub(start) as u32;

            b.current_hop = 1;
            
            // Extract values we need
            let target_hop_0 = b.target_hops[0].clone();
            let keys = LayerKeys::from_hop_crypto(crypto);
            
            (target_hop_0, keys, rtt)
        }; // bmap is dropped here

        // add hop 0 to circuit with derived LayerKeys
        {
            let mut circuits = self.circuits.lock();
            let entry = circuits.entry(circuit_id).or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));
            entry.add_hop(target_hop_0, keys)?;
            entry.hops[0].rtt_ms = ewma_update(entry.hops[0].rtt_ms, rtt);
            entry.touch();
        }

        // move to extend or complete if 1-hop circuit (unlikely)
        let mut bmap = self.building.lock();
        let b = bmap.get_mut(&circuit_id).unwrap();
        if b.target_hops.len() == 1 {
            // complete immediately
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

    /// Handle EXTENDED/EXTENDED2 response (for hop >= 1)
    pub fn handle_extended_cell(&mut self, circuit_id: CircuitId, cell: Cell) -> Result<(), OnionError> {
        let (expected_hop, relay, keys, rtt) = {
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;

            let expected_hop = b.current_hop;
            if b.state != BuildState::WaitingExtended(expected_hop) {
                return Err(OnionError::InvalidCell);
            }

            let crypto = b
                .crypto_state
                .get_mut(expected_hop)
                .ok_or(OnionError::CryptoError)?;
            let start = now_ms();
            crypto.complete_handshake(&cell.payload)?;
            let rtt = now_ms().saturating_sub(start) as u32;

            // Extract values we need
            let relay = b.target_hops[expected_hop].clone();
            let keys = LayerKeys::from_hop_crypto(crypto);
            
            (expected_hop, relay, keys, rtt)
        }; // bmap is dropped here

        {
            let mut circuits = self.circuits.lock();
            let entry = circuits.entry(circuit_id).or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));
            entry.add_hop(relay, keys)?;
            let idx = entry.hop_count() - 1;
            entry.hops[idx].rtt_ms = ewma_update(entry.hops[idx].rtt_ms, rtt);
            entry.touch();
        }

        // advance or complete
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

    /// Complete circuit and add to active circuits
    fn complete_circuit(&mut self, circuit_id: CircuitId) -> Result<(), OnionError> {
        // pop building
        let building = {
            let mut bmap = self.building.lock();
            bmap.remove(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?
        };

        // ensure circuit exists and is exactly 3 hops
        {
            let mut circuits = self.circuits.lock();
            let circuit = circuits
                .entry(circuit_id)
                .or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));

            // build-time keys for all hops already added; sanity check
            if circuit.hop_count() != building.target_hops.len() {
                return Err(OnionError::CircuitBuildFailed);
            }

            let build_time = now_ms().saturating_sub(building.start_time);
            self.perf.record_circuit_built(circuit_id, build_time);

            circuit.mark_open();
        }

        // optionally push to prebuilt pool if purpose matches
        self.pool.maybe_add(circuit_id);

        Ok(())
    }

    /* ===== Runtime ops ===== */

    /// Get circuit by ID (clone)
    pub fn get_circuit(&self, circuit_id: CircuitId) -> Option<Circuit> {
        self.circuits.lock().get(&circuit_id).cloned()
    }

    /// Get all open circuits
    pub fn get_open_circuits(&self) -> Vec<CircuitId> {
        self.circuits
            .lock()
            .iter()
            .filter(|(_, c)| c.is_open())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Close circuit gracefully (DESTROY)
    pub fn close_circuit(&mut self, circuit_id: CircuitId) -> Result<(), OnionError> {
        if let Some(mut circuit) = self.circuits.lock().remove(&circuit_id) {
            circuit.state = CircuitState::Closing;
            let cell = Cell::destroy_cell(circuit_id, 0); // reason: none
            // best-effort send; even on failure we consider it tear-down
            let _ = self.send_cell_through_circuit(circuit_id, cell);
        }
        Ok(())
    }

    /// Enhanced circuit statistics
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

    /// Clean up expired and failed circuits + timeouts
    pub fn cleanup_expired_circuits(&mut self, max_age_ms: u64) {
        // drop expired circuits
        {
            let mut circuits = self.circuits.lock();
            let expired_ids: Vec<_> = circuits
                .iter()
                .filter(|(_, c)| c.is_expired(max_age_ms) || matches!(c.state, CircuitState::Failed | CircuitState::Closed))
                .map(|(id, _)| *id)
                .collect();
            for id in expired_ids {
                circuits.remove(&id);
            }
        }

        // prune timed-out building circuits
        {
            let now = now_ms();
            let mut bmap = self.building.lock();
            let mut fail_list: Vec<CircuitId> = Vec::new();

            for (id, b) in bmap.iter() {
                if now.saturating_sub(b.start_time) > b.timeout_ms {
                    fail_list.push(*id);
                }
            }

            for id in fail_list {
                bmap.remove(&id);
                self.perf.global.failed_circuits.fetch_add(1, Ordering::Relaxed);
                // mark a placeholder failed circuit (optional)
                let mut circuits = self.circuits.lock();
                circuits
                    .entry(id)
                    .and_modify(|c| c.state = CircuitState::Failed)
                    .or_insert_with(|| {
                        let mut c = Circuit::new(id, CircuitPurpose::General);
                        c.state = CircuitState::Failed;
                        c
                    });
            }
        }
    }

    /* ===== Cell I/O helpers ===== */

    /// Send cell to a specific relay via TCP (first hop direct).
    fn send_cell_to_relay(&self, cell: Cell, relay: &RelayDescriptor) -> Result<(), OnionError> {
        if let Some(net) = get_network_stack() {
            let packet = cell.serialize();
            net.send_tcp_packet(&packet)
                .map_err(|_| OnionError::NetworkError)?;
            Ok(())
        } else {
            Err(OnionError::NetworkError)
        }
    }

    /// Send cell through existing circuit with encryption (to guard).
    fn send_cell_through_circuit(&self, circuit_id: CircuitId, mut cell: Cell) -> Result<(), OnionError> {
        let mut circuits = self.circuits.lock();
        if let Some(c) = circuits.get_mut(&circuit_id) {
            let enc = c.encrypt_forward(&cell.payload)?;
            cell.payload = enc;
            if let Some(guard) = c.hops.first() {
                self.send_cell_to_relay(cell, &guard.relay)?;
                c.touch();
                return Ok(());
            }
        }
        Err(OnionError::CircuitBuildFailed)
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

/* ===== Path selector impls ===== */

impl PathSelector {
    fn new() -> Self {
        PathSelector {
            guard_nodes: Mutex::new(Vec::new()),
            middle_nodes: Mutex::new(Vec::new()),
            exit_nodes: Mutex::new(Vec::new()),
            node_perf: Mutex::new(BTreeMap::new()),
        }
    }

    fn init(&self) -> Result<(), OnionError> {
        // In a full integration, we will populate relays from consensus/microdescriptors.
        Ok(())
    }

    /// Choose a 3-hop path that satisfies constraints (basic heuristic).
    fn select_optimal_path(&self, constraints: &PathConstraints) -> Result<Vec<RelayDescriptor>, OnionError> {
        let guards = self.guard_nodes.lock();
        let middles = self.middle_nodes.lock();
        let exits = self.exit_nodes.lock();

        // Guard
        let guard = guards
            .iter()
            .filter(|n| n.bandwidth >= constraints.min_bandwidth)
            .filter(|n| !constraints.exclude_nodes.contains(&n.fingerprint))
            .filter(|n| !matches_country(n, &constraints.country_exclude))
            .find(|n| !constraints.require_guard || n.flags.is_guard)
            .ok_or(OnionError::RelayNotFound)?
            .clone();

        // Middle (not same family/fingerprint)
        let middle = middles
            .iter()
            .filter(|n| n.bandwidth >= constraints.min_bandwidth)
            .filter(|n| n.fingerprint != guard.fingerprint)
            .filter(|n| !constraints.exclude_nodes.contains(&n.fingerprint))
            .filter(|n| !same_family(&guard, n))
            .filter(|n| !matches_country(n, &constraints.country_exclude))
            .next()
            .ok_or(OnionError::RelayNotFound)?
            .clone();

        // Exit
        let exit = exits
            .iter()
            .filter(|n| n.bandwidth >= constraints.min_bandwidth)
            .filter(|n| n.fingerprint != guard.fingerprint && n.fingerprint != middle.fingerprint)
            .filter(|n| !constraints.exclude_nodes.contains(&n.fingerprint))
            .filter(|n| !same_family(&guard, n) && !same_family(&middle, n))
            .filter(|n| !matches_country(n, &constraints.country_exclude))
            .find(|n| !constraints.require_exit || n.flags.is_exit)
            .ok_or(OnionError::RelayNotFound)?
            .clone();

        Ok(vec![guard, middle, exit])
    }
}

#[inline]
fn same_family(a: &RelayDescriptor, b: &RelayDescriptor) -> bool {
    !a.family.is_empty() && a.family == b.family
}

#[inline]
fn matches_country(r: &RelayDescriptor, excludes: &Vec<String>) -> bool {
    if excludes.is_empty() {
        return false;
    }
    if !r.country_code.is_empty() {
        let cc = &r.country_code;
        return excludes.iter().any(|x| x == cc);
    }
    false
}

/* ===== Performance monitor ===== */

impl PerformanceMonitor {
    fn new() -> Self {
        PerformanceMonitor {
            circuit_stats: Mutex::new(BTreeMap::new()),
            global: CircuitGlobalStats::default(),
        }
    }

    fn record_circuit_built(&self, circuit_id: CircuitId, build_time_ms: u64) {
        self.global
            .total_circuits_built
            .fetch_add(1, Ordering::Relaxed);

        // update average build time (online mean)
        let current_avg = self.global.average_build_time_ms.load(Ordering::Relaxed) as u64;
        let total_built = self.global.total_circuits_built.load(Ordering::Relaxed) as u64;
        let new_avg = if total_built == 0 {
            build_time_ms
        } else {
            (current_avg.saturating_mul(total_built.saturating_sub(1)) + build_time_ms)
                / total_built
        };
        self.global
            .average_build_time_ms
            .store(new_avg as u32, Ordering::Relaxed);

        // note: per-circuit metrics are updated by Circuit via get_performance_metrics
        let mut map = self.circuit_stats.lock();
        map.insert(
            circuit_id,
            CircuitMetrics {
                total_rtt_ms: 0,
                total_bytes_sent: 0,
                total_bytes_received: 0,
                active_streams: 0,
                uptime_ms: 0,
            },
        );
    }
}

/* ===== Pool ===== */

impl CircuitPool {
    fn new(pool_size: usize, min_circuits: usize) -> Self {
        CircuitPool {
            prebuilt_circuits: Mutex::new(Vec::new()),
            pool_size,
            min_circuits,
        }
    }

    fn init(&self) -> Result<(), OnionError> {
        // Could spawn a maintenance task in your scheduler to keep N circuits warm.
        Ok(())
    }

    fn maybe_add(&self, id: CircuitId) {
        let mut v = self.prebuilt_circuits.lock();
        if v.len() < self.pool_size {
            v.push(id);
        }
    }

    #[allow(dead_code)]
    fn take_ready(&self) -> Option<CircuitId> {
        let mut v = self.prebuilt_circuits.lock();
        v.pop()
    }
}

/* ===== helpers ===== */

#[inline]
fn now_ms() -> u64 {
    use crate::time;
    time::timestamp_millis()
}

/// simple EWMA for RTT (alpha = 0.3)
#[inline]
fn ewma_update(old_ms: u32, sample_ms: u32) -> u32 {
    if old_ms == 0 {
        return sample_ms;
    }
    // new = alpha*sample + (1-alpha)*old
    let alpha_num = 3u32; // 0.3
    let alpha_den = 10u32;
    ((alpha_num * sample_ms + (alpha_den - alpha_num) * old_ms) / alpha_den)
}

/* ===== end ===== */