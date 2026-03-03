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

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use crate::network::onion::StreamId;

#[derive(Debug, Clone)]
pub(crate) struct InterceptorConfig {
    pub(crate) enabled: bool,
    pub(crate) intercept_tcp: bool,
    pub(crate) intercept_dns: bool,
    pub(crate) bypass_ips: Vec<[u8; 4]>,
    pub(crate) bypass_ranges: Vec<([u8; 4], u8)>,
    pub(crate) bypass_local: bool,
    pub(crate) allowed_ports: Vec<u16>,
    pub(crate) blocked_ports: Vec<u16>,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            intercept_tcp: true,
            intercept_dns: true,
            bypass_ips: Vec::new(),
            bypass_ranges: Vec::new(),
            bypass_local: true,
            allowed_ports: Vec::new(),
            blocked_ports: Vec::new(),
        }
    }
}

pub(super) struct TransparentConnection {
    pub(super) stream_id: StreamId,
    pub(super) bytes_sent: u64,
    pub(super) bytes_received: u64,
    pub(super) last_activity: u64,
}

#[derive(Debug, Default)]
pub(super) struct InterceptorStats {
    pub(super) packets_intercepted: AtomicU64,
    pub(super) connections_established: AtomicU64,
    pub(super) connections_failed: AtomicU64,
    pub(super) bytes_sent: AtomicU64,
    pub(super) bytes_received: AtomicU64,
    pub(super) dns_queries_intercepted: AtomicU64,
}

pub(super) fn is_local_network(ip: [u8; 4]) -> bool {
    if ip[0] == 10 {
        return true;
    }
    if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
        return true;
    }
    if ip[0] == 192 && ip[1] == 168 {
        return true;
    }
    if ip[0] == 127 {
        return true;
    }
    if ip[0] == 169 && ip[1] == 254 {
        return true;
    }
    false
}

pub(super) fn ip_in_subnet(ip: [u8; 4], subnet: [u8; 4], prefix: u8) -> bool {
    let mask = if prefix >= 32 {
        0xFFFFFFFF_u32
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let ip_val = u32::from_be_bytes(ip);
    let subnet_val = u32::from_be_bytes(subnet);
    (ip_val & mask) == (subnet_val & mask)
}
