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

//! Directory service type definitions

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64};

/// Exit policy rule for relay selection
#[derive(Debug, Clone, PartialEq)]
pub enum ExitRule {
    Accept { addr: String, port: String },
    Reject { addr: String, port: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExitPolicy {
    Accept,
    Reject,
}

impl ExitRule {
    pub fn allows_connection(&self, addr: &str, port: u16) -> bool {
        match self {
            ExitRule::Accept { addr: rule_addr, port: rule_port } => {
                self.matches_pattern(rule_addr, addr) && self.matches_port(rule_port, port)
            },
            ExitRule::Reject { addr: rule_addr, port: rule_port } => {
                !(self.matches_pattern(rule_addr, addr) && self.matches_port(rule_port, port))
            },
        }
    }

    fn matches_pattern(&self, pattern: &str, addr: &str) -> bool {
        if pattern == "*" { return true; }
        pattern == addr
    }

    fn matches_port(&self, pattern: &str, port: u16) -> bool {
        if pattern == "*" { return true; }
        if let Ok(p) = pattern.parse::<u16>() {
            return p == port;
        }
        false
    }
}

/// Directory authority information
#[derive(Debug, Clone)]
pub struct DirectoryAuthority {
    pub nickname: String,
    pub ed25519_identity: Option<[u8; 32]>,
    pub identity_fingerprint: Vec<u8>,
    pub address: [u8; 4],
    pub dir_port: u16,
    pub or_port: u16,
}

/// Relay descriptor (populated from consensus+microdesc)
#[derive(Debug, Clone)]
pub struct RelayDescriptor {
    pub nickname: String,
    pub identity_digest: [u8; 20],
    pub ed25519_identity: [u8; 32],
    pub ntor_onion_key: Vec<u8>,
    pub address: [u8; 4],
    pub port: u16,
    pub dir_port: u16,
    pub bandwidth: u64,
    pub measured_bandwidth: u64,
    pub flags: RelayFlags,
    pub fingerprint: [u8; 20],
    pub family: String,
    pub country_code: String,
    pub as_number: u32,
    pub consensus_weight: u32,
    pub guard_probability: f32,
    pub middle_probability: f32,
    pub exit_probability: f32,
    /// Exit policy - ports this relay accepts (empty = non-exit or unknown)
    pub exit_ports: Vec<PortRange>,
}

impl RelayDescriptor {
    /// Check if this relay supports exiting to the given port
    pub fn allows_port(&self, port: u16) -> bool {
        // If no exit ports specified but is_exit flag set, assume it supports common ports
        if self.exit_ports.is_empty() {
            return self.flags.is_exit;
        }
        self.exit_ports.iter().any(|r| r.contains(port))
    }

    /// Check if this relay supports all required ports
    pub fn allows_all_ports(&self, ports: &[u16]) -> bool {
        if ports.is_empty() {
            return self.flags.is_exit;
        }
        ports.iter().all(|&p| self.allows_port(p))
    }
}

/// Relay flags from consensus
#[derive(Debug, Clone, Default)]
pub struct RelayFlags {
    pub is_authority: bool,
    pub is_bad_exit: bool,
    pub is_exit: bool,
    pub is_fast: bool,
    pub is_guard: bool,
    pub is_hsdir: bool,
    pub is_no_ed_consensus: bool,
    pub is_running: bool,
    pub is_stable: bool,
    pub is_stable_uptime: bool,
    pub is_v2dir: bool,
    pub is_valid: bool,
}

/// Network consensus document (parsed subset)
#[derive(Debug, Clone)]
pub struct NetworkConsensus {
    pub raw_body: Vec<u8>,
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
    pub consensus_method: u32,
    pub voting_delay: (u32, u32),
    pub params: BTreeMap<String, i32>,
    pub authorities: Vec<DirectoryAuthorityHeader>,
    pub relays: Vec<ConsensusEntry>,
    pub signatures: Vec<ConsensusSignature>,
    pub bandwidth_weights: BandwidthWeights,
}

/// Header info for authorities as listed in consensus
#[derive(Debug, Clone)]
pub struct DirectoryAuthorityHeader {
    pub nickname: String,
    pub identity: [u8; 20],
    pub address: [u8; 4],
    pub dir_port: u16,
    pub or_port: u16,
}

/// Entry in consensus for a single relay
#[derive(Debug, Clone)]
pub struct ConsensusEntry {
    pub nickname: String,
    pub identity_digest: [u8; 20],
    pub descriptor_digest: [u8; 20],
    pub microdesc_sha256: Option<[u8; 32]>,
    pub published: u64,
    pub address: [u8; 4],
    pub or_port: u16,
    pub dir_port: u16,
    pub flags: RelayFlags,
    pub version: Option<String>,
    pub bandwidth: Option<u64>,
    pub measured_bandwidth: Option<u64>,
    pub ed25519_id: Option<[u8; 32]>,
}

/// Authority signature on consensus
#[derive(Debug, Clone)]
pub struct ConsensusSignature {
    pub identity: [u8; 20],
    pub signing_alg: SigAlg,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigAlg {
    Ed25519,
    Unknown,
}

/// Bandwidth weights for path selection
#[derive(Debug, Clone, Default)]
pub struct BandwidthWeights {
    pub weight_scale: u32,
    pub wbd: u32, pub wbe: u32, pub wbg: u32, pub wbm: u32,
    pub wed: u32, pub wee: u32, pub weg: u32, pub wem: u32,
    pub wgd: u32, pub wgg: u32, pub wgm: u32,
    pub wmd: u32, pub wme: u32, pub wmg: u32, pub wmm: u32,
}

/// Router status enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum RouterStatus {
    Running,
    Down,
    Hibernating,
    Unknown,
}

/// Directory service statistics
#[derive(Debug, Default)]
pub struct DirectoryStats {
    pub consensus_fetches: AtomicU32,
    pub descriptor_fetches: AtomicU32,
    pub authorities_contacted: AtomicU32,
    pub consensus_parse_errors: AtomicU32,
    pub last_consensus_age: AtomicU64,
    pub relay_count: AtomicU32,
    pub guard_count: AtomicU32,
    pub exit_count: AtomicU32,
}

/// Path bias statistics for security analysis
#[derive(Debug, Clone, Default)]
pub struct PathBiasStats {
    pub circuits_attempted: u32,
    pub circuits_succeeded: u32,
    pub success_rate: f32,
    pub last_updated: u64,
}

/// Parsed microdescriptor data
#[derive(Default)]
pub struct MicroParsed {
    pub ntor_key: [u8; 32],
    pub family: String,
    /// Exit policy summary - ports this relay accepts (empty = rejects all exits)
    pub exit_ports: Vec<PortRange>,
}

/// Port range for exit policy
#[derive(Debug, Clone, Copy, Default)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    pub fn new(min: u16, max: u16) -> Self {
        Self { min, max }
    }

    pub fn single(port: u16) -> Self {
        Self { min: port, max: port }
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port <= self.max
    }
}
