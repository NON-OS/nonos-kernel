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


use alloc::{string::String, vec::Vec};
use crate::network::onion::directory::RelayDescriptor;
use crate::network::onion::crypto::LayerKeys;

pub type CircuitId = u32;

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Building,
    Open,
    Closing,
    Closed,
    Failed,
}

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
pub enum CircuitPurpose {
    General,
    HiddenService,
    HSDir,
    Introduction,
    Rendezvous,
    Testing,
    Preemptive,
}

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
pub struct CircuitMetrics {
    pub total_rtt_ms: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub active_streams: u16,
    pub uptime_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_circuits: usize,
    pub open_circuits: usize,
    pub building_circuits: usize,
    pub failed_circuits: u32,
    pub total_built: u32,
    pub average_build_time_ms: u32,
}
