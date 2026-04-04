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

use crate::runtime::*;

#[test]
fn test_zerostate_register_capsule() {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("zerostate_test", alloc::vec![], quotas);
    assert_eq!(cap.name, "zerostate_test");
}

#[test]
fn test_zerostate_register_capsule_with_peers() {
    let quotas = capsule::CapsuleQuotas::default();
    let peers = alloc::vec!["peer_a", "peer_b"];
    let cap = zerostate::register_capsule("zerostate_peers_test", peers, quotas);
    let p = cap.peers.read();
    assert_eq!(p.len(), 2);
}

#[test]
fn test_zerostate_register_capsule_with_custom_quotas() {
    let quotas = capsule::CapsuleQuotas {
        inbox_capacity: 2048,
        max_msg_bytes: 512 * 1024,
        max_bytes_per_sec: 2 << 20,
        heartbeat_interval_ms: 3000,
    };
    let cap = zerostate::register_capsule("zerostate_custom_quotas", alloc::vec![], quotas);
    assert_eq!(cap.quotas.inbox_capacity, 2048);
    assert_eq!(cap.quotas.max_msg_bytes, 524288);
}

#[test]
fn test_zerostate_get_capsule_by_name() {
    let quotas = capsule::CapsuleQuotas::default();
    zerostate::register_capsule("get_by_name_test", alloc::vec![], quotas);
    let found = zerostate::get_capsule_by_name("get_by_name_test");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "get_by_name_test");
}

#[test]
fn test_zerostate_get_capsule_by_name_nonexistent() {
    let found = zerostate::get_capsule_by_name("nonexistent_capsule_abc");
    assert!(found.is_none());
}

#[test]
fn test_zerostate_heartbeat_for_registered() {
    let quotas = capsule::CapsuleQuotas::default();
    zerostate::register_capsule("heartbeat_test_capsule", alloc::vec![], quotas);
    zerostate::heartbeat("heartbeat_test_capsule");
}

#[test]
fn test_zerostate_heartbeat_for_nonexistent() {
    zerostate::heartbeat("nonexistent_heartbeat_capsule");
}

#[test]
fn test_zerostate_poll_capsule_none_when_empty() {
    let quotas = capsule::CapsuleQuotas::default();
    zerostate::register_capsule("poll_empty_test", alloc::vec![], quotas);
    let msg = zerostate::poll_capsule("poll_empty_test");
    assert!(msg.is_none());
}

#[test]
fn test_zerostate_poll_capsule_nonexistent() {
    let msg = zerostate::poll_capsule("definitely_not_registered");
    assert!(msg.is_none());
}

#[test]
fn test_zerostate_register_multiple_capsules() {
    let quotas = capsule::CapsuleQuotas::default();
    let cap1 = zerostate::register_capsule("multi_cap_1", alloc::vec![], quotas.clone());
    let cap2 = zerostate::register_capsule("multi_cap_2", alloc::vec![], quotas.clone());
    let cap3 = zerostate::register_capsule("multi_cap_3", alloc::vec![], quotas);

    assert_ne!(cap1.id, cap2.id);
    assert_ne!(cap2.id, cap3.id);
    assert_ne!(cap1.id, cap3.id);
}

#[test]
fn test_zerostate_capsule_initial_health() {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("health_test", alloc::vec![], quotas);
    assert_eq!(cap.health(), capsule::CapsuleState::Stopped);
}

#[test]
fn test_zerostate_monitor_once_no_panic() {
    zerostate::monitor_once();
}

#[test]
fn test_zerostate_monitor_once_multiple_calls() {
    zerostate::monitor_once();
    zerostate::monitor_once();
    zerostate::monitor_once();
}

#[test]
fn test_zerostate_capsule_ids_increasing() {
    let quotas = capsule::CapsuleQuotas::default();
    let cap1 = zerostate::register_capsule("increasing_id_1", alloc::vec![], quotas.clone());
    let cap2 = zerostate::register_capsule("increasing_id_2", alloc::vec![], quotas);
    assert!(cap2.id.get() > cap1.id.get());
}

#[test]
fn test_zerostate_register_with_empty_peers() {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("empty_peers_cap", alloc::vec![], quotas);
    let peers = cap.peers.read();
    assert!(peers.is_empty());
}

#[test]
fn test_zerostate_register_with_many_peers() {
    let quotas = capsule::CapsuleQuotas::default();
    let peers = alloc::vec!["p1", "p2", "p3", "p4", "p5"];
    let cap = zerostate::register_capsule("many_peers_cap", peers, quotas);
    let p = cap.peers.read();
    assert_eq!(p.len(), 5);
}

#[test]
fn test_zerostate_capsule_name_preserved() {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("preserved_name", alloc::vec![], quotas);
    assert_eq!(cap.name, "preserved_name");
    let found = zerostate::get_capsule_by_name("preserved_name");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "preserved_name");
}

#[test]
fn test_zerostate_quotas_applied() {
    let quotas = capsule::CapsuleQuotas {
        inbox_capacity: 100,
        max_msg_bytes: 200,
        max_bytes_per_sec: 300,
        heartbeat_interval_ms: 400,
    };
    let cap = zerostate::register_capsule("quotas_applied_test", alloc::vec![], quotas);
    assert_eq!(cap.quotas.inbox_capacity, 100);
    assert_eq!(cap.quotas.max_msg_bytes, 200);
    assert_eq!(cap.quotas.max_bytes_per_sec, 300);
    assert_eq!(cap.quotas.heartbeat_interval_ms, 400);
}

#[test]
fn test_zerostate_stop_capsule_not_found() {
    let result = zerostate::stop_capsule("never_registered_stop");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "capsule not found");
}

#[test]
fn test_zerostate_start_capsule_not_found() {
    let token = crate::syscall::capabilities::CapabilityToken::empty();
    let result = zerostate::start_capsule("never_registered_start", &token);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "capsule not found");
}
