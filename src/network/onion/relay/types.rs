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
use super::connection::ORConnection;

pub const CONNECT_TIMEOUT_MS: u64 = 15_000;
pub const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 30_000;
pub const IO_READ_TIMEOUT_MS: u64 = 5_000;
pub const IO_WRITE_TIMEOUT_MS: u64 = 10_000;

pub const DEFAULT_OR_PORT: u16 = 9201;

pub const DEFAULT_DIR_PORT: u16 = 9230;

pub const DEFAULT_SOCKS_PORT: u16 = 9050;

pub const DEFAULT_BANDWIDTH_RATE: u64 = 0;

pub type LinkId = u64;

pub struct OnionRelay {
    pub connection: ORConnection,
    pub status: RelayStatus,
    pub config: RelayConfig,
}

#[derive(Debug, Clone)]
pub struct ExitPolicyRule {
    pub accept: bool,
    pub port_min: u16,
    pub port_max: u16,
    pub address_pattern: String,
}

impl ExitPolicyRule {
    pub fn accept_ports(port_min: u16, port_max: u16) -> Self {
        Self {
            accept: true,
            port_min,
            port_max,
            address_pattern: String::new(),
        }
    }

    pub fn reject_all() -> Self {
        Self {
            accept: false,
            port_min: 0,
            port_max: 65535,
            address_pattern: String::new(),
        }
    }

    pub fn matches(&self, _address: &str, port: u16) -> bool {
        if self.port_min == 0 && self.port_max == 65535 {
            return true;
        }
        port >= self.port_min && port <= self.port_max
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExitPolicy {
    pub rules: Vec<ExitPolicyRule>,
}

impl ExitPolicy {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn reduced() -> Self {
        let mut policy = Self::new();
        policy.rules.push(ExitPolicyRule::accept_ports(80, 80));
        policy.rules.push(ExitPolicyRule::accept_ports(443, 443));
        policy.rules.push(ExitPolicyRule::reject_all());
        policy
    }

    pub fn reject_all() -> Self {
        let mut policy = Self::new();
        policy.rules.push(ExitPolicyRule::reject_all());
        policy
    }

    pub fn allows_exit(&self, address: &str, port: u16) -> bool {
        for rule in &self.rules {
            if rule.matches(address, port) {
                return rule.accept;
            }
        }
        false
    }

    pub fn parse(policy_str: &str) -> Result<Self, &'static str> {
        let mut policy = Self::new();

        for part in policy_str.split_whitespace() {
            if part.starts_with("accept") || part.starts_with("reject") {
                let accept = part.starts_with("accept");
                if let Some(colon_pos) = part.find(':') {
                    let port_spec = &part[colon_pos + 1..];
                    let (port_min, port_max) = if port_spec == "*" {
                        (0, 65535)
                    } else if let Some(dash_pos) = port_spec.find('-') {
                        let min: u16 = port_spec[..dash_pos].parse().unwrap_or(0);
                        let max: u16 = port_spec[dash_pos + 1..].parse().unwrap_or(65535);
                        (min, max)
                    } else if let Some(_comma_pos) = port_spec.find(',') {
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

#[derive(Clone)]
pub struct RelayConfig {
    pub connect_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
    pub io_timeout_ms: u64,

    pub or_port: u16,
    pub dir_port: u16,
    pub socks_port: u16,

    pub bandwidth_rate: u64,
    pub bandwidth_burst: u64,

    pub nickname: String,
    pub contact_info: String,

    pub exit_policy: ExitPolicy,

    pub is_exit: bool,
    pub is_guard: bool,
    pub is_bridge: bool,

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
    pub fn middle_relay(nickname: &str, or_port: u16) -> Self {
        Self {
            nickname: String::from(nickname),
            or_port,
            exit_policy: ExitPolicy::reject_all(),
            is_exit: false,
            ..Default::default()
        }
    }

    pub fn exit_relay(nickname: &str, or_port: u16) -> Self {
        Self {
            nickname: String::from(nickname),
            or_port,
            exit_policy: ExitPolicy::reduced(),
            is_exit: true,
            ..Default::default()
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    ClientOnly,
    MiddleRelay,
    ExitRelay,
    GuardRelay,
    BridgeRelay,
}
