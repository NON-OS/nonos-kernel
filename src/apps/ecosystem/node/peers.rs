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


extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use spin::RwLock;

static PEERS: RwLock<BTreeMap<String, PeerInfo>> = RwLock::new(BTreeMap::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Connecting,
    Connected,
    Syncing,
    Idle,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub enode: String,
    pub ip: String,
    pub port: u16,
    pub status: PeerStatus,
    pub direction: PeerDirection,
    pub client_version: String,
    pub protocol_version: u32,
    pub head_block: u64,
    pub difficulty: u128,
    pub latency_ms: u32,
    pub connected_at: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl PeerInfo {
    pub fn new(id: &str, enode: &str, ip: &str, port: u16) -> Self {
        Self {
            id: String::from(id),
            enode: String::from(enode),
            ip: String::from(ip),
            port,
            status: PeerStatus::Connecting,
            direction: PeerDirection::Outbound,
            client_version: String::new(),
            protocol_version: 0,
            head_block: 0,
            difficulty: 0,
            latency_ms: 0,
            connected_at: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(
            self.status,
            PeerStatus::Connected | PeerStatus::Syncing | PeerStatus::Idle
        )
    }

    pub fn connection_duration(&self) -> u64 {
        if self.connected_at == 0 {
            return 0;
        }
        crate::time::timestamp_secs().saturating_sub(self.connected_at)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn short_id(&self) -> String {
        if self.id.len() > 16 {
            alloc::format!("{}...", &self.id[..16])
        } else {
            self.id.clone()
        }
    }
}

pub fn add_peer(peer: PeerInfo) {
    let mut peers = PEERS.write();
    peers.insert(peer.id.clone(), peer);
}

pub fn remove_peer(id: &str) -> Option<PeerInfo> {
    let mut peers = PEERS.write();
    peers.remove(id)
}

pub fn get_peer(id: &str) -> Option<PeerInfo> {
    let peers = PEERS.read();
    peers.get(id).cloned()
}

pub fn get_peers() -> Vec<PeerInfo> {
    let peers = PEERS.read();
    peers.values().cloned().collect()
}

pub fn get_connected_peers() -> Vec<PeerInfo> {
    let peers = PEERS.read();
    peers.values().filter(|p| p.is_connected()).cloned().collect()
}

pub fn peer_count() -> usize {
    PEERS.read().len()
}

pub fn connected_peer_count() -> usize {
    let peers = PEERS.read();
    peers.values().filter(|p| p.is_connected()).count()
}

pub fn update_peer_status(id: &str, status: PeerStatus) {
    let mut peers = PEERS.write();
    if let Some(peer) = peers.get_mut(id) {
        peer.status = status;
        if status == PeerStatus::Connected && peer.connected_at == 0 {
            peer.connected_at = crate::time::timestamp_secs();
        }
    }
}

pub fn update_peer_head(id: &str, head_block: u64, difficulty: u128) {
    let mut peers = PEERS.write();
    if let Some(peer) = peers.get_mut(id) {
        peer.head_block = head_block;
        peer.difficulty = difficulty;
    }
}

pub fn update_peer_latency(id: &str, latency_ms: u32) {
    let mut peers = PEERS.write();
    if let Some(peer) = peers.get_mut(id) {
        peer.latency_ms = latency_ms;
    }
}

pub fn update_peer_traffic(id: &str, bytes_sent: u64, bytes_received: u64) {
    let mut peers = PEERS.write();
    if let Some(peer) = peers.get_mut(id) {
        peer.bytes_sent += bytes_sent;
        peer.bytes_received += bytes_received;
    }
}

pub fn set_peer_client_info(id: &str, client_version: &str, protocol_version: u32) {
    let mut peers = PEERS.write();
    if let Some(peer) = peers.get_mut(id) {
        peer.client_version = String::from(client_version);
        peer.protocol_version = protocol_version;
    }
}

pub fn get_best_peer() -> Option<PeerInfo> {
    let peers = PEERS.read();
    peers
        .values()
        .filter(|p| p.is_connected())
        .max_by_key(|p| p.head_block)
        .cloned()
}

pub fn get_peers_by_head_block(min_block: u64) -> Vec<PeerInfo> {
    let peers = PEERS.read();
    peers
        .values()
        .filter(|p| p.is_connected() && p.head_block >= min_block)
        .cloned()
        .collect()
}

pub fn disconnect_all() {
    let mut peers = PEERS.write();
    for peer in peers.values_mut() {
        peer.status = PeerStatus::Disconnected;
    }
}

pub fn clear_peers() {
    let mut peers = PEERS.write();
    peers.clear();
}

pub fn get_total_traffic() -> (u64, u64) {
    let peers = PEERS.read();
    let sent: u64 = peers.values().map(|p| p.bytes_sent).sum();
    let received: u64 = peers.values().map(|p| p.bytes_received).sum();
    (sent, received)
}

pub fn get_average_latency() -> u32 {
    let peers = PEERS.read();
    let connected: Vec<&PeerInfo> = peers.values().filter(|p| p.is_connected()).collect();
    if connected.is_empty() {
        return 0;
    }

    let total: u32 = connected.iter().map(|p| p.latency_ms).sum();
    total / connected.len() as u32
}
