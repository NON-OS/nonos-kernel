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

use crate::daemon::*;

#[test]
fn test_peer_info_empty() {
    let peer = PeerInfo::empty();
    assert_eq!(peer.id.0, [0u8; 32]);
    assert!(!peer.connected);
    assert_eq!(peer.latency_ms, 0);
    assert_eq!(peer.bytes_sent, 0);
    assert_eq!(peer.bytes_received, 0);
    assert_eq!(peer.requests_served, 0);
    assert_eq!(peer.last_seen, 0);
}

#[test]
fn test_p2p_state_new() {
    let state = P2PState::new();
    assert_eq!(state.status, ConnectionStatus::Disconnected);
    assert_eq!(state.peer_count, 0);
    assert_eq!(state.active_connections, 0);
    assert_eq!(state.total_bytes_sent, 0);
    assert_eq!(state.total_bytes_received, 0);
    assert_eq!(state.bootstrap_progress, 0);
    assert!(!state.mixing_enabled);
    assert_eq!(state.cache_size_mb, 256);
}

#[test]
fn test_p2p_state_connect() {
    let mut state = P2PState::new();
    state.connect();
    assert_eq!(state.status, ConnectionStatus::Connecting);
}

#[test]
fn test_p2p_state_disconnect() {
    let mut state = P2PState::new();
    state.connect();
    state.active_connections = 5;
    state.bootstrap_progress = 50;
    state.disconnect();
    assert_eq!(state.status, ConnectionStatus::Disconnected);
    assert_eq!(state.active_connections, 0);
    assert_eq!(state.bootstrap_progress, 0);
}

#[test]
fn test_p2p_state_set_connected() {
    let mut state = P2PState::new();
    state.connect();
    state.set_connected();
    assert_eq!(state.status, ConnectionStatus::Connected);
    assert_eq!(state.bootstrap_progress, 100);
}

#[test]
fn test_p2p_state_add_peer() {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    assert!(state.add_peer(id));
    assert_eq!(state.peer_count, 1);
}

#[test]
fn test_p2p_state_add_peer_multiple() {
    let mut state = P2PState::new();
    for i in 0..10 {
        let id = NodeId::from_bytes([i; 32]);
        assert!(state.add_peer(id));
    }
    assert_eq!(state.peer_count, 10);
}

#[test]
fn test_p2p_state_add_peer_max() {
    let mut state = P2PState::new();
    for i in 0..MAX_PEERS {
        let id = NodeId::from_bytes([i as u8; 32]);
        assert!(state.add_peer(id));
    }
    assert_eq!(state.peer_count, MAX_PEERS);
    let id = NodeId::from_bytes([0xFF; 32]);
    assert!(!state.add_peer(id));
    assert_eq!(state.peer_count, MAX_PEERS);
}

#[test]
fn test_p2p_state_add_peer_initializes_fields() {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    state.add_peer(id);
    let peer = state.get_peer(&id).unwrap();
    assert!(!peer.connected);
    assert_eq!(peer.latency_ms, 0);
    assert_eq!(peer.bytes_sent, 0);
}

#[test]
fn test_p2p_state_remove_peer() {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    state.add_peer(id);
    assert!(state.remove_peer(&id));
    assert_eq!(state.peer_count, 0);
}

#[test]
fn test_p2p_state_remove_peer_not_found() {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    assert!(!state.remove_peer(&id));
}

#[test]
fn test_p2p_state_remove_peer_middle() {
    let mut state = P2PState::new();
    let id1 = NodeId::from_bytes([1u8; 32]);
    let id2 = NodeId::from_bytes([2u8; 32]);
    let id3 = NodeId::from_bytes([3u8; 32]);
    state.add_peer(id1);
    state.add_peer(id2);
    state.add_peer(id3);
    assert!(state.remove_peer(&id2));
    assert_eq!(state.peer_count, 2);
    assert!(state.get_peer(&id1).is_some());
    assert!(state.get_peer(&id2).is_none());
    assert!(state.get_peer(&id3).is_some());
}

#[test]
fn test_p2p_state_get_peer() {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    state.add_peer(id);
    let peer = state.get_peer(&id);
    assert!(peer.is_some());
    assert_eq!(peer.unwrap().id.0, id.0);
}

#[test]
fn test_p2p_state_get_peer_not_found() {
    let state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    assert!(state.get_peer(&id).is_none());
}

#[test]
fn test_p2p_state_connected_peers_none() {
    let state = P2PState::new();
    assert_eq!(state.connected_peers(), 0);
}

#[test]
fn test_p2p_state_connected_peers_some() {
    let mut state = P2PState::new();
    for i in 0..5 {
        let id = NodeId::from_bytes([i; 32]);
        state.add_peer(id);
    }
    state.peers[0].connected = true;
    state.peers[2].connected = true;
    assert_eq!(state.connected_peers(), 2);
}

#[test]
fn test_p2p_state_enable_mixing() {
    let mut state = P2PState::new();
    assert!(!state.mixing_enabled);
    state.enable_mixing();
    assert!(state.mixing_enabled);
}

#[test]
fn test_p2p_state_disable_mixing() {
    let mut state = P2PState::new();
    state.enable_mixing();
    state.disable_mixing();
    assert!(!state.mixing_enabled);
}

#[test]
fn test_p2p_state_set_cache_size() {
    let mut state = P2PState::new();
    state.set_cache_size(512);
    assert_eq!(state.cache_size_mb, 512);
}

#[test]
fn test_p2p_state_set_cache_size_max() {
    let mut state = P2PState::new();
    state.set_cache_size(8192);
    assert_eq!(state.cache_size_mb, 4096);
}

#[test]
fn test_p2p_state_set_cache_size_zero() {
    let mut state = P2PState::new();
    state.set_cache_size(0);
    assert_eq!(state.cache_size_mb, 0);
}

#[test]
fn test_p2p_state_default() {
    let state = P2PState::default();
    assert_eq!(state.status, ConnectionStatus::Disconnected);
    assert_eq!(state.peer_count, 0);
    assert!(!state.mixing_enabled);
}

#[test]
fn test_mixer_stats_new() {
    let stats = MixerStats::new();
    assert_eq!(stats.requests_mixed, 0);
    assert_eq!(stats.bytes_mixed, 0);
    assert_eq!(stats.avg_latency_ms, 0);
    assert_eq!(stats.cache_hit_rate, 0);
}

#[test]
fn test_mixer_stats_default() {
    let stats = MixerStats::default();
    assert_eq!(stats.requests_mixed, 0);
    assert_eq!(stats.bytes_mixed, 0);
}

#[test]
fn test_p2p_constants() {
    assert_eq!(MAX_PEERS, 64);
    assert_eq!(MAX_CONNECTIONS, 32);
}
