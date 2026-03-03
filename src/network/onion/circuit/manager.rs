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


use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::network::onion::OnionError;
use crate::network::onion::cell::Cell;
use crate::network::onion::crypto::{HopCrypto, LayerKeys};
use crate::network::onion::directory::RelayDescriptor;
use crate::network::get_network_stack;

use super::types::{CircuitId, CircuitState, CircuitPurpose, PathConstraints, ExtendInfo, LinkSpecifier, CircuitStats};
use super::circuit::Circuit;
use super::building::{BuildingCircuit, BuildState};
use super::path::PathSelector;
use super::pool::CircuitPool;
use super::performance::PerformanceMonitor;
use super::util::{now_ms, ewma_update, strip_len_prefix_if_any};

pub struct CircuitManager {
    circuits: Mutex<BTreeMap<CircuitId, Circuit>>,
    next_circuit_id: AtomicU32,
    building: Mutex<BTreeMap<CircuitId, BuildingCircuit>>,
    path_selection: PathSelector,
    perf: PerformanceMonitor,
    pool: CircuitPool,
}

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
        if relays.is_empty() {
            relays = self.path_selection.select_optimal_path(&PathConstraints::default())?;
        }
        if relays.len() != 3 {
            return Err(OnionError::InsufficientRelays);
        }

        let circuit_id = self.next_circuit_id.fetch_add(1, Ordering::Relaxed);
        let building = BuildingCircuit {
            id: circuit_id,
            target_hops: relays.clone(),
            current_hop: 0,
            state: BuildState::SendingCreate,
            crypto_state: Vec::new(),
            start_time: now_ms(),
            timeout_ms: 60_000,
        };
        self.building.lock().insert(circuit_id, building);
        self.send_create_cell(circuit_id, &relays[0])?;
        Ok(circuit_id)
    }

    fn send_create_cell(&self, circuit_id: CircuitId, guard: &RelayDescriptor) -> Result<(), OnionError> {
        let mut hop_crypto = HopCrypto::new(&guard.ntor_onion_key)?;
        let cell = Cell::create2_cell(circuit_id, 2, hop_crypto.handshake_data());
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
                LinkSpecifier::Ed25519 { identity: target.ed25519_identity },
            ],
        };
        let mut hop_crypto = HopCrypto::new(&target.ntor_onion_key)?;
        let cell = Cell::extend2_cell(circuit_id, extend_info, 2, hop_crypto.handshake_data());
        self.send_cell_through_circuit(circuit_id, cell)?;
        if let Some(mut bmap) = self.building.try_lock() {
            if let Some(b) = bmap.get_mut(&circuit_id) {
                b.crypto_state.push(hop_crypto);
            }
        }
        Ok(())
    }

    pub fn handle_created_cell(&mut self, circuit_id: CircuitId, cell: Cell) -> Result<(), OnionError> {
        let (target_hop_0, keys, rtt) = {
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            if b.state != BuildState::WaitingCreated {
                return Err(OnionError::InvalidCell);
            }

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
        let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
        if b.target_hops.len() == 1 {
            drop(bmap);
            self.complete_circuit(circuit_id)?;
        } else {
            b.state = BuildState::SendingExtend(1);
            let relay1 = b.target_hops[1].clone();
            drop(bmap);
            self.send_extend_cell(circuit_id, &relay1)?;
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            b.state = BuildState::WaitingExtended(1);
        }
        Ok(())
    }

    pub fn handle_extended_cell(&mut self, circuit_id: CircuitId, cell: Cell) -> Result<(), OnionError> {
        let (_hop, relay, keys, rtt) = {
            let mut bmap = self.building.lock();
            let b = bmap.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            let expected_hop = b.current_hop;
            if b.state != BuildState::WaitingExtended(expected_hop) {
                return Err(OnionError::InvalidCell);
            }

            let crypto = b.crypto_state.get_mut(expected_hop).ok_or(OnionError::CryptoError)?;
            let start = now_ms();
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
        let b2 = bmap2.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
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
            let b3 = bmap3.get_mut(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            b3.state = BuildState::WaitingExtended(next);
        }
        Ok(())
    }

    fn complete_circuit(&mut self, circuit_id: CircuitId) -> Result<(), OnionError> {
        let building = {
            let mut bmap = self.building.lock();
            bmap.remove(&circuit_id).ok_or(OnionError::CircuitBuildFailed)?
        };
        {
            let mut circuits = self.circuits.lock();
            let circuit = circuits.entry(circuit_id).or_insert_with(|| Circuit::new(circuit_id, CircuitPurpose::General));
            if circuit.hop_count() != building.target_hops.len() {
                return Err(OnionError::CircuitBuildFailed);
            }
            let build_time = now_ms().saturating_sub(building.start_time);
            self.perf.record_circuit_built(circuit_id, build_time);
            circuit.mark_open();
        }
        self.pool.maybe_add(circuit_id);
        Ok(())
    }

    pub fn get_circuit(&self, circuit_id: CircuitId) -> Option<Circuit> {
        self.circuits.lock().get(&circuit_id).cloned()
    }

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
            for id in expired_ids {
                circuits.remove(&id);
            }
        }
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

            let encrypted_payload = circuit.encrypt_forward(&cell.payload)?;
            cell.payload = encrypted_payload;
            cell.circuit_id = circuit_id;

            if let Some(first_relay) = circuit.hops.first() {
                let relay_ref = first_relay.relay.clone();
                circuit.touch();
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
