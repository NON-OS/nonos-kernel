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

//! P2P networking for cache mixing.

use super::node::NodeId;
use super::types::ConnectionStatus;

pub const MAX_PEERS: usize = 64;
pub const MAX_CONNECTIONS: usize = 32;

#[derive(Clone, Copy)]
pub struct PeerInfo {
    pub id: NodeId,
    pub connected: bool,
    pub latency_ms: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_served: u32,
    pub last_seen: u64,
}

impl PeerInfo {
    pub const fn empty() -> Self {
        Self {
            id: NodeId([0u8; 32]),
            connected: false,
            latency_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
            requests_served: 0,
            last_seen: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct P2PState {
    pub status: ConnectionStatus,
    pub peers: [PeerInfo; MAX_PEERS],
    pub peer_count: usize,
    pub active_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub bootstrap_progress: u8,
    pub mixing_enabled: bool,
    pub cache_size_mb: u32,
}

impl P2PState {
    pub const fn new() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            peers: [PeerInfo::empty(); MAX_PEERS],
            peer_count: 0,
            active_connections: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            bootstrap_progress: 0,
            mixing_enabled: false,
            cache_size_mb: 256,
        }
    }

    pub fn connect(&mut self) {
        self.status = ConnectionStatus::Connecting;
    }

    pub fn disconnect(&mut self) {
        self.status = ConnectionStatus::Disconnected;
        self.active_connections = 0;
        self.bootstrap_progress = 0;
    }

    pub fn set_connected(&mut self) {
        self.status = ConnectionStatus::Connected;
        self.bootstrap_progress = 100;
    }

    pub fn add_peer(&mut self, id: NodeId) -> bool {
        if self.peer_count >= MAX_PEERS {
            return false;
        }

        self.peers[self.peer_count] = PeerInfo {
            id,
            connected: false,
            latency_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
            requests_served: 0,
            last_seen: 0,
        };
        self.peer_count += 1;
        true
    }

    pub fn remove_peer(&mut self, id: &NodeId) -> bool {
        for i in 0..self.peer_count {
            if self.peers[i].id.0 == id.0 {
                for j in i..self.peer_count - 1 {
                    self.peers[j] = self.peers[j + 1];
                }
                self.peer_count -= 1;
                return true;
            }
        }
        false
    }

    pub fn get_peer(&self, id: &NodeId) -> Option<&PeerInfo> {
        for i in 0..self.peer_count {
            if self.peers[i].id.0 == id.0 {
                return Some(&self.peers[i]);
            }
        }
        None
    }

    pub fn connected_peers(&self) -> usize {
        let mut count = 0;
        for i in 0..self.peer_count {
            if self.peers[i].connected {
                count += 1;
            }
        }
        count
    }

    pub fn enable_mixing(&mut self) {
        self.mixing_enabled = true;
    }

    pub fn disable_mixing(&mut self) {
        self.mixing_enabled = false;
    }

    pub fn set_cache_size(&mut self, mb: u32) {
        self.cache_size_mb = mb.min(4096);
    }
}

impl Default for P2PState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct MixerStats {
    pub requests_mixed: u64,
    pub bytes_mixed: u64,
    pub avg_latency_ms: u32,
    pub cache_hit_rate: u8,
}

impl MixerStats {
    pub const fn new() -> Self {
        Self {
            requests_mixed: 0,
            bytes_mixed: 0,
            avg_latency_ms: 0,
            cache_hit_rate: 0,
        }
    }
}

impl Default for MixerStats {
    fn default() -> Self {
        Self::new()
    }
}
