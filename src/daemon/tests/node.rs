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
fn test_node_id_from_bytes() {
    let bytes = [0x42u8; 32];
    let id = NodeId::from_bytes(bytes);
    assert_eq!(id.0, bytes);
}

#[test]
fn test_node_id_as_bytes() {
    let bytes = [0x42u8; 32];
    let id = NodeId::from_bytes(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn test_node_id_short_id_prefix() {
    let bytes = [0u8; 32];
    let id = NodeId::from_bytes(bytes);
    let short = id.short_id();
    assert_eq!(&short[..5], b"nxnd_");
}

#[test]
fn test_node_id_short_id_length() {
    let bytes = [0xABu8; 32];
    let id = NodeId::from_bytes(bytes);
    let short = id.short_id();
    assert_eq!(short.len(), 20);
}

#[test]
fn test_node_id_short_id_hex_encoding() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xAB;
    bytes[1] = 0xCD;
    let id = NodeId::from_bytes(bytes);
    let short = id.short_id();
    assert_eq!(&short[5..9], b"abcd");
}

#[test]
fn test_node_info_generate_status() {
    let info = NodeInfo::generate();
    assert_eq!(info.status, NodeStatus::Stopped);
}

#[test]
fn test_node_info_generate_tier() {
    let info = NodeInfo::generate();
    assert_eq!(info.tier, NodeTier::Bronze);
}

#[test]
fn test_node_info_generate_quality() {
    let info = NodeInfo::generate();
    assert_eq!(info.quality.uptime, 0);
    assert_eq!(info.quality.success_rate, 0);
}

#[test]
fn test_node_info_generate_staked() {
    let info = NodeInfo::generate();
    assert!(info.staked.is_zero());
    assert!(info.pending_rewards.is_zero());
}

#[test]
fn test_node_info_generate_counters() {
    let info = NodeInfo::generate();
    assert_eq!(info.streak, 0);
    assert_eq!(info.uptime_secs, 0);
    assert_eq!(info.active_connections, 0);
    assert_eq!(info.total_requests, 0);
    assert_eq!(info.successful_requests, 0);
}

#[test]
fn test_node_info_generate_nickname() {
    let info = NodeInfo::generate();
    assert_eq!(&info.nickname[..11], b"nonos-node-");
    assert_eq!(info.nickname_len, 19);
}

#[test]
fn test_node_info_set_nickname() {
    let mut info = NodeInfo::generate();
    info.set_nickname(b"my-custom-node");
    assert_eq!(info.get_nickname(), b"my-custom-node");
    assert_eq!(info.nickname_len, 14);
}

#[test]
fn test_node_info_set_nickname_truncates() {
    let mut info = NodeInfo::generate();
    let long_name = [b'x'; 64];
    info.set_nickname(&long_name);
    assert_eq!(info.nickname_len, 32);
}

#[test]
fn test_node_info_set_nickname_empty() {
    let mut info = NodeInfo::generate();
    info.set_nickname(b"");
    assert_eq!(info.get_nickname(), b"");
    assert_eq!(info.nickname_len, 0);
}

#[test]
fn test_node_info_success_rate_zero_requests() {
    let info = NodeInfo::generate();
    assert_eq!(info.success_rate(), 0);
}

#[test]
fn test_node_info_success_rate_all_successful() {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 100;
    assert_eq!(info.success_rate(), 100);
}

#[test]
fn test_node_info_success_rate_partial() {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 75;
    assert_eq!(info.success_rate(), 75);
}

#[test]
fn test_node_info_success_rate_none() {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 0;
    assert_eq!(info.success_rate(), 0);
}

#[test]
fn test_node_info_update_quality_success_rate() {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 80;
    info.update_quality();
    assert_eq!(info.quality.success_rate, 80);
}

#[test]
fn test_node_info_update_quality_uptime_full_day() {
    let mut info = NodeInfo::generate();
    info.uptime_secs = 86400;
    info.update_quality();
    assert_eq!(info.quality.uptime, 100);
}

#[test]
fn test_node_info_update_quality_uptime_partial() {
    let mut info = NodeInfo::generate();
    info.uptime_secs = 43200;
    info.update_quality();
    assert_eq!(info.quality.uptime, 50);
}

#[test]
fn test_node_info_update_quality_uptime_more_than_day() {
    let mut info = NodeInfo::generate();
    info.uptime_secs = 172800;
    info.update_quality();
    assert_eq!(info.quality.uptime, 100);
}

#[test]
fn test_node_info_start() {
    let mut info = NodeInfo::generate();
    assert_eq!(info.status, NodeStatus::Stopped);
    info.start();
    assert_eq!(info.status, NodeStatus::Starting);
}

#[test]
fn test_node_info_stop() {
    let mut info = NodeInfo::generate();
    info.start();
    info.stop();
    assert_eq!(info.status, NodeStatus::Stopped);
}

#[test]
fn test_node_info_default() {
    let info = NodeInfo::default();
    assert_eq!(info.status, NodeStatus::Stopped);
    assert_eq!(info.tier, NodeTier::Bronze);
}

#[test]
fn test_node_info_clone() {
    let info = NodeInfo::generate();
    let cloned = info.clone();
    assert_eq!(info.status, cloned.status);
    assert_eq!(info.tier, cloned.tier);
    assert_eq!(info.nickname_len, cloned.nickname_len);
}
