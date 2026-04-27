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
use crate::test::framework::TestResult;

pub(crate) fn test_peer_info_empty() -> TestResult {
    let peer = PeerInfo::empty();
    if peer.id.0 != [0u8; 32] {
        return TestResult::Fail;
    }
    if peer.connected {
        return TestResult::Fail;
    }
    if peer.latency_ms != 0 {
        return TestResult::Fail;
    }
    if peer.bytes_sent != 0 {
        return TestResult::Fail;
    }
    if peer.bytes_received != 0 {
        return TestResult::Fail;
    }
    if peer.requests_served != 0 {
        return TestResult::Fail;
    }
    if peer.last_seen != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_new() -> TestResult {
    let state = P2PState::new();
    if state.status != ConnectionStatus::Disconnected {
        return TestResult::Fail;
    }
    if state.peer_count != 0 {
        return TestResult::Fail;
    }
    if state.active_connections != 0 {
        return TestResult::Fail;
    }
    if state.total_bytes_sent != 0 {
        return TestResult::Fail;
    }
    if state.total_bytes_received != 0 {
        return TestResult::Fail;
    }
    if state.bootstrap_progress != 0 {
        return TestResult::Fail;
    }
    if state.mixing_enabled {
        return TestResult::Fail;
    }
    if state.cache_size_mb != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_connect() -> TestResult {
    let mut state = P2PState::new();
    state.connect();
    if state.status != ConnectionStatus::Connecting {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_disconnect() -> TestResult {
    let mut state = P2PState::new();
    state.connect();
    state.active_connections = 5;
    state.bootstrap_progress = 50;
    state.disconnect();
    if state.status != ConnectionStatus::Disconnected {
        return TestResult::Fail;
    }
    if state.active_connections != 0 {
        return TestResult::Fail;
    }
    if state.bootstrap_progress != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_set_connected() -> TestResult {
    let mut state = P2PState::new();
    state.connect();
    state.set_connected();
    if state.status != ConnectionStatus::Connected {
        return TestResult::Fail;
    }
    if state.bootstrap_progress != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_add_peer() -> TestResult {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    if !state.add_peer(id) {
        return TestResult::Fail;
    }
    if state.peer_count != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_add_peer_multiple() -> TestResult {
    let mut state = P2PState::new();
    for i in 0..10 {
        let id = NodeId::from_bytes([i; 32]);
        if !state.add_peer(id) {
            return TestResult::Fail;
        }
    }
    if state.peer_count != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_add_peer_max() -> TestResult {
    let mut state = P2PState::new();
    for i in 0..MAX_PEERS {
        let id = NodeId::from_bytes([i as u8; 32]);
        if !state.add_peer(id) {
            return TestResult::Fail;
        }
    }
    if state.peer_count != MAX_PEERS {
        return TestResult::Fail;
    }
    let id = NodeId::from_bytes([0xFF; 32]);
    if state.add_peer(id) {
        return TestResult::Fail;
    }
    if state.peer_count != MAX_PEERS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_add_peer_initializes_fields() -> TestResult {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    state.add_peer(id);
    let peer = state.get_peer(&id).unwrap();
    if peer.connected {
        return TestResult::Fail;
    }
    if peer.latency_ms != 0 {
        return TestResult::Fail;
    }
    if peer.bytes_sent != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_remove_peer() -> TestResult {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    state.add_peer(id);
    if !state.remove_peer(&id) {
        return TestResult::Fail;
    }
    if state.peer_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_remove_peer_not_found() -> TestResult {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    if state.remove_peer(&id) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_remove_peer_middle() -> TestResult {
    let mut state = P2PState::new();
    let id1 = NodeId::from_bytes([1u8; 32]);
    let id2 = NodeId::from_bytes([2u8; 32]);
    let id3 = NodeId::from_bytes([3u8; 32]);
    state.add_peer(id1);
    state.add_peer(id2);
    state.add_peer(id3);
    if !state.remove_peer(&id2) {
        return TestResult::Fail;
    }
    if state.peer_count != 2 {
        return TestResult::Fail;
    }
    if state.get_peer(&id1).is_none() {
        return TestResult::Fail;
    }
    if state.get_peer(&id2).is_some() {
        return TestResult::Fail;
    }
    if state.get_peer(&id3).is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_get_peer() -> TestResult {
    let mut state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    state.add_peer(id);
    let peer = state.get_peer(&id);
    if peer.is_none() {
        return TestResult::Fail;
    }
    if peer.unwrap().id.0 != id.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_get_peer_not_found() -> TestResult {
    let state = P2PState::new();
    let id = NodeId::from_bytes([1u8; 32]);
    if !state.get_peer(&id).is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_connected_peers_none() -> TestResult {
    let state = P2PState::new();
    if state.connected_peers() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_connected_peers_some() -> TestResult {
    let mut state = P2PState::new();
    for i in 0..5 {
        let id = NodeId::from_bytes([i; 32]);
        state.add_peer(id);
    }
    state.peers[0].connected = true;
    state.peers[2].connected = true;
    if state.connected_peers() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_enable_mixing() -> TestResult {
    let mut state = P2PState::new();
    if state.mixing_enabled {
        return TestResult::Fail;
    }
    state.enable_mixing();
    if !state.mixing_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_disable_mixing() -> TestResult {
    let mut state = P2PState::new();
    state.enable_mixing();
    state.disable_mixing();
    if state.mixing_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_set_cache_size() -> TestResult {
    let mut state = P2PState::new();
    state.set_cache_size(512);
    if state.cache_size_mb != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_set_cache_size_max() -> TestResult {
    let mut state = P2PState::new();
    state.set_cache_size(8192);
    if state.cache_size_mb != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_set_cache_size_zero() -> TestResult {
    let mut state = P2PState::new();
    state.set_cache_size(0);
    if state.cache_size_mb != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_state_default() -> TestResult {
    let state = P2PState::default();
    if state.status != ConnectionStatus::Disconnected {
        return TestResult::Fail;
    }
    if state.peer_count != 0 {
        return TestResult::Fail;
    }
    if state.mixing_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixer_stats_new() -> TestResult {
    let stats = MixerStats::new();
    if stats.requests_mixed != 0 {
        return TestResult::Fail;
    }
    if stats.bytes_mixed != 0 {
        return TestResult::Fail;
    }
    if stats.avg_latency_ms != 0 {
        return TestResult::Fail;
    }
    if stats.cache_hit_rate != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixer_stats_default() -> TestResult {
    let stats = MixerStats::default();
    if stats.requests_mixed != 0 {
        return TestResult::Fail;
    }
    if stats.bytes_mixed != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_p2p_constants() -> TestResult {
    if MAX_PEERS != 64 {
        return TestResult::Fail;
    }
    if MAX_CONNECTIONS != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
