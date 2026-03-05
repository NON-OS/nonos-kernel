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

//! Relay types and configuration for Anyone network

use alloc::string::String;
use alloc::vec::Vec;
use super::connection::ORConnection;

/// Timeout defaults (milliseconds)
pub const CONNECT_TIMEOUT_MS: u64 = 15_000;
pub const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 30_000;
pub const IO_READ_TIMEOUT_MS: u64 = 5_000;
pub const IO_WRITE_TIMEOUT_MS: u64 = 10_000;

/// Default Anyone OR port
pub const DEFAULT_OR_PORT: u16 = 9201;

/// Default Anyone directory port
pub const DEFAULT_DIR_PORT: u16 = 9230;

/// Default SOCKS port
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Maximum bandwidth (bytes per second), 0 = unlimited
pub const DEFAULT_BANDWIDTH_RATE: u64 = 0;

/// Link identifier type
pub type LinkId = u64;

/// Onion relay for routing traffic
pub struct OnionRelay {
    pub connection: ORConnection,
    pub status: RelayStatus,
    pub config: RelayConfig,
}

/// Exit policy rule
#[derive(Debug, Clone)]
pub struct ExitPolicyRule {
    /// True for accept, false for reject
    pub accept: bool,
    /// Port or port range (0 = any)
    pub port_min: u16,
    pub port_max: u16,
    /// Address pattern (empty = any)
    pub address_pattern: String,
}

impl ExitPolicyRule {
    /// Create accept rule for specific ports
    pub fn accept_ports(port_min: u16, port_max: u16) -> Self {
        Self {
            accept: true,
            port_min,
            port_max,
            address_pattern: String::new(),
        }
    }

    /// Create reject all rule
    pub fn reject_all() -> Self {
        Self {
            accept: false,
            port_min: 0,
            port_max: 65535,
            address_pattern: String::new(),
        }
    }

    /// Check if this rule matches the given address and port
    pub fn matches(&self, _address: &str, port: u16) -> bool {
        if self.port_min == 0 && self.port_max == 65535 {
            return true; // Match all ports
        }
        port >= self.port_min && port <= self.port_max
    }
}

/// Exit policy - ordered list of rules
#[derive(Debug, Clone, Default)]
pub struct ExitPolicy {
    pub rules: Vec<ExitPolicyRule>,
}

impl ExitPolicy {
    /// Create new empty policy
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create default reduced exit policy (web traffic only)
    pub fn reduced() -> Self {
        let mut policy = Self::new();
        // Accept common web ports
        policy.rules.push(ExitPolicyRule::accept_ports(80, 80));
        policy.rules.push(ExitPolicyRule::accept_ports(443, 443));
        // Reject everything else
        policy.rules.push(ExitPolicyRule::reject_all());
        policy
    }

    /// Create policy that rejects all exits (middle/guard only)
    pub fn reject_all() -> Self {
        let mut policy = Self::new();
        policy.rules.push(ExitPolicyRule::reject_all());
        policy
    }

    /// Check if exit to address:port is allowed
    pub fn allows_exit(&self, address: &str, port: u16) -> bool {
        for rule in &self.rules {
            if rule.matches(address, port) {
                return rule.accept;
            }
        }
        // Default deny
        false
    }

    /// Parse exit policy from string (e.g., "accept *:80,443 reject *:*")
    pub fn parse(policy_str: &str) -> Result<Self, &'static str> {
        let mut policy = Self::new();

        for part in policy_str.split_whitespace() {
            if part.starts_with("accept") || part.starts_with("reject") {
                let accept = part.starts_with("accept");
                // Find the port specification after the colon
                if let Some(colon_pos) = part.find(':') {
                    let port_spec = &part[colon_pos + 1..];
                    let (port_min, port_max) = if port_spec == "*" {
                        (0, 65535)
                    } else if let Some(dash_pos) = port_spec.find('-') {
                        let min: u16 = port_spec[..dash_pos].parse().unwrap_or(0);
                        let max: u16 = port_spec[dash_pos + 1..].parse().unwrap_or(65535);
                        (min, max)
                    } else if let Some(_comma_pos) = port_spec.find(',') {
                        // Handle comma-separated ports by creating multiple rules
                        for port_str in port_spec.split(',') {
                            if let Ok(port) = port_str.parse::<u16>() {
                                policy.rules.push(ExitPolicyRule {
                                    accept,
                                    port_min: port,
                                    port_max: port,
                                    address_pattern: String::new(),
                                });
                            }
                        }
                        continue;
                    } else {
                        let port: u16 = port_spec.parse().unwrap_or(0);
                        (port, port)
                    };

                    policy.rules.push(ExitPolicyRule {
                        accept,
                        port_min,
                        port_max,
                        address_pattern: String::new(),
                    });
                }
            }
        }

        if policy.rules.is_empty() {
            return Err("Empty or invalid policy");
        }
        Ok(policy)
    }
}

/// Relay configuration
#[derive(Clone)]
pub struct RelayConfig {
    /// Timeouts
    pub connect_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
    pub io_timeout_ms: u64,

    /// Network ports
    pub or_port: u16,
    pub dir_port: u16,
    pub socks_port: u16,

    /// Bandwidth limits (bytes per second, 0 = unlimited)
    pub bandwidth_rate: u64,
    pub bandwidth_burst: u64,

    /// Relay identity
    pub nickname: String,
    pub contact_info: String,

    /// Exit policy
    pub exit_policy: ExitPolicy,

    /// Relay flags
    pub is_exit: bool,
    pub is_guard: bool,
    pub is_bridge: bool,

    /// Advertised address (empty = auto-detect)
    pub advertised_address: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: CONNECT_TIMEOUT_MS,
            handshake_timeout_ms: TLS_HANDSHAKE_TIMEOUT_MS,
            io_timeout_ms: IO_READ_TIMEOUT_MS,
            or_port: DEFAULT_OR_PORT,
            dir_port: DEFAULT_DIR_PORT,
            socks_port: DEFAULT_SOCKS_PORT,
            bandwidth_rate: DEFAULT_BANDWIDTH_RATE,
            bandwidth_burst: DEFAULT_BANDWIDTH_RATE * 2,
            nickname: String::new(),
            contact_info: String::new(),
            exit_policy: ExitPolicy::reject_all(),
            is_exit: false,
            is_guard: false,
            is_bridge: false,
            advertised_address: String::new(),
        }
    }
}

impl RelayConfig {
    /// Create a middle-only relay config (no exit)
    pub fn middle_relay(nickname: &str, or_port: u16) -> Self {
        Self {
            nickname: String::from(nickname),
            or_port,
            exit_policy: ExitPolicy::reject_all(),
            is_exit: false,
            ..Default::default()
        }
    }

    /// Create an exit relay config with reduced policy
    pub fn exit_relay(nickname: &str, or_port: u16) -> Self {
        Self {
            nickname: String::from(nickname),
            or_port,
            exit_policy: ExitPolicy::reduced(),
            is_exit: true,
            ..Default::default()
        }
    }

    /// Create a guard relay config
    pub fn guard_relay(nickname: &str, or_port: u16, bandwidth_rate: u64) -> Self {
        Self {
            nickname: String::from(nickname),
            or_port,
            bandwidth_rate,
            bandwidth_burst: bandwidth_rate * 2,
            exit_policy: ExitPolicy::reject_all(),
            is_guard: true,
            ..Default::default()
        }
    }
}

/// Relay status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Failed,
}

/// Relay operational mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Client only - no relay services
    ClientOnly,
    /// Middle relay - forward traffic but no exit
    MiddleRelay,
    /// Exit relay - can connect to destinations
    ExitRelay,
    /// Guard relay - entry point for circuits
    GuardRelay,
    /// Bridge relay - unlisted entry point
    BridgeRelay,
}
