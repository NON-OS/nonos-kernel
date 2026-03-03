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
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::network::onion::cell::{Cell, CellProcessor};
use crate::network::onion::circuit::{CircuitId, CircuitManager};
use crate::network::onion::directory::DirectoryService;
use crate::network::onion::relay::{RelayConfig, RelayManager, RelayMode};
use crate::network::onion::security::init_security;
use crate::network::onion::stream::{StreamId, StreamManager};

use super::error::OnionError;
use super::types::{RelayStats, KeyManager, RouteOptimizer};

pub struct OnionRouter {
    pub circuit_manager: CircuitManager,
    pub directory_service: DirectoryService,
    pub relay_manager: RelayManager,
    pub stream_manager: StreamManager,
    pub cell_processor: CellProcessor,
    pub key_manager: KeyManager,
    pub route_optimizer: RouteOptimizer,
    pub is_relay: AtomicBool,
    pub relay_mode: AtomicU8,
    pub relay_stats: RelayStats,
    pub relay_config: Option<RelayConfig>,
}

impl OnionRouter {
    pub fn new() -> Self {
        OnionRouter {
            circuit_manager: CircuitManager::new(),
            directory_service: DirectoryService::new(),
            relay_manager: RelayManager::new(),
            stream_manager: StreamManager::new(),
            cell_processor: CellProcessor::new(),
            key_manager: KeyManager::new(),
            route_optimizer: RouteOptimizer::new(),
            is_relay: AtomicBool::new(false),
            relay_mode: AtomicU8::new(RelayMode::ClientOnly as u8),
            relay_stats: RelayStats::new(),
            relay_config: None,
        }
    }

    pub fn init(&mut self) -> Result<(), OnionError> {
        init_security()?;
        self.directory_service.init()?;
        self.circuit_manager.init()?;
        Ok(())
    }

    pub fn create_circuit(&mut self, exit_policy: Option<String>) -> Result<CircuitId, OnionError> {
        let relays = if let Some(ref policy_str) = exit_policy {
            let required_ports = Self::parse_required_ports(policy_str);
            self.directory_service.select_path_with_exit_policy(&required_ports)?
        } else {
            self.directory_service.select_path()?
        };

        if relays.len() != 3 {
            return Err(OnionError::InsufficientRelays);
        }

        let circuit_id = self.circuit_manager.build_circuit(relays)?;
        self.relay_stats.inc_circuits();
        Ok(circuit_id)
    }

    fn parse_required_ports(policy_str: &str) -> Vec<u16> {
        if policy_str == "*" {
            return Vec::new();
        }

        policy_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    }

    pub fn create_stream(&mut self, circuit_id: CircuitId, target: String, port: u16) -> Result<StreamId, OnionError> {
        let stream_id = self.stream_manager.create_stream(circuit_id, target, port)?;
        self.relay_stats.inc_streams();
        Ok(stream_id)
    }

    pub fn send_data(&mut self, stream_id: StreamId, data: Vec<u8>) -> Result<(), OnionError> {
        self.stream_manager.send_data(stream_id, &data)
    }

    pub fn recv_data(&mut self, stream_id: StreamId) -> Result<Vec<u8>, OnionError> {
        self.stream_manager.recv_data(stream_id)
    }

    pub fn process_cell(&mut self, cell: Cell) -> Result<(), OnionError> {
        self.cell_processor
            .process_cell(cell, &mut self.circuit_manager, &mut self.stream_manager)?;
        self.relay_stats.inc_cells();
        Ok(())
    }

    pub fn enable_relay_mode(&mut self, relay_config: RelayConfig) -> Result<(), OnionError> {
        if relay_config.nickname.is_empty() {
            return Err(OnionError::InvalidConfig);
        }

        if relay_config.or_port == 0 {
            return Err(OnionError::InvalidConfig);
        }

        let mode = if relay_config.is_bridge {
            RelayMode::BridgeRelay
        } else if relay_config.is_exit {
            RelayMode::ExitRelay
        } else if relay_config.is_guard {
            RelayMode::GuardRelay
        } else {
            RelayMode::MiddleRelay
        };

        if relay_config.bandwidth_rate > 0 {
            self.relay_manager.set_bandwidth_limit(
                relay_config.bandwidth_rate,
                relay_config.bandwidth_burst,
            );
        }

        self.relay_config = Some(relay_config.clone());

        self.relay_manager.configure(relay_config)?;

        self.is_relay.store(true, Ordering::SeqCst);
        self.relay_mode.store(mode as u8, Ordering::SeqCst);

        self.key_manager.generate_relay_keys()?;

        Ok(())
    }

    pub fn disable_relay_mode(&mut self) -> Result<(), OnionError> {
        self.is_relay.store(false, Ordering::SeqCst);
        self.relay_mode.store(RelayMode::ClientOnly as u8, Ordering::SeqCst);
        self.relay_config = None;
        self.relay_manager.shutdown()?;
        Ok(())
    }

    pub fn get_stats(&self) -> &RelayStats {
        &self.relay_stats
    }

    pub fn is_relay_mode(&self) -> bool {
        self.is_relay.load(Ordering::Relaxed)
    }

    pub fn get_relay_mode(&self) -> RelayMode {
        match self.relay_mode.load(Ordering::Relaxed) {
            1 => RelayMode::MiddleRelay,
            2 => RelayMode::ExitRelay,
            3 => RelayMode::GuardRelay,
            4 => RelayMode::BridgeRelay,
            _ => RelayMode::ClientOnly,
        }
    }

    pub fn get_relay_config(&self) -> Option<&RelayConfig> {
        self.relay_config.as_ref()
    }

    pub fn allows_exit(&self, address: &str, port: u16) -> bool {
        if let Some(ref config) = self.relay_config {
            if config.is_exit {
                return config.exit_policy.allows_exit(address, port);
            }
        }
        false
    }
}

impl Default for OnionRouter {
    fn default() -> Self {
        Self::new()
    }
}
