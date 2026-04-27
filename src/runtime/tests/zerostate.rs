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
use crate::test::framework::TestResult;

pub(crate) fn test_zerostate_register_capsule() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("zerostate_test", alloc::vec![], quotas);
    if cap.name != "zerostate_test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_register_capsule_with_peers() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let peers = alloc::vec!["peer_a", "peer_b"];
    let cap = zerostate::register_capsule("zerostate_peers_test", peers, quotas);
    let p = cap.peers.read();
    if p.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_register_capsule_with_custom_quotas() -> TestResult {
    let quotas = capsule::CapsuleQuotas {
        inbox_capacity: 2048,
        max_msg_bytes: 512 * 1024,
        max_bytes_per_sec: 2 << 20,
        heartbeat_interval_ms: 3000,
    };
    let cap = zerostate::register_capsule("zerostate_custom_quotas", alloc::vec![], quotas);
    if cap.quotas.inbox_capacity != 2048 {
        return TestResult::Fail;
    }
    if cap.quotas.max_msg_bytes != 524288 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_get_capsule_by_name() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    zerostate::register_capsule("get_by_name_test", alloc::vec![], quotas);
    let found = zerostate::get_capsule_by_name("get_by_name_test");
    if !found.is_some() {
        return TestResult::Fail;
    }
    if found.unwrap().name != "get_by_name_test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_get_capsule_by_name_nonexistent() -> TestResult {
    let found = zerostate::get_capsule_by_name("nonexistent_capsule_abc");
    if !found.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_heartbeat_for_registered() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    zerostate::register_capsule("heartbeat_test_capsule", alloc::vec![], quotas);
    zerostate::heartbeat("heartbeat_test_capsule");
    TestResult::Pass
}

pub(crate) fn test_zerostate_heartbeat_for_nonexistent() -> TestResult {
    zerostate::heartbeat("nonexistent_heartbeat_capsule");
    TestResult::Pass
}

pub(crate) fn test_zerostate_poll_capsule_none_when_empty() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    zerostate::register_capsule("poll_empty_test", alloc::vec![], quotas);
    let msg = zerostate::poll_capsule("poll_empty_test");
    if !msg.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_poll_capsule_nonexistent() -> TestResult {
    let msg = zerostate::poll_capsule("definitely_not_registered");
    if !msg.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_register_multiple_capsules() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let cap1 = zerostate::register_capsule("multi_cap_1", alloc::vec![], quotas.clone());
    let cap2 = zerostate::register_capsule("multi_cap_2", alloc::vec![], quotas.clone());
    let cap3 = zerostate::register_capsule("multi_cap_3", alloc::vec![], quotas);

    if cap1.id == cap2.id {
        return TestResult::Fail;
    }
    if cap2.id == cap3.id {
        return TestResult::Fail;
    }
    if cap1.id == cap3.id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_capsule_initial_health() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("health_test", alloc::vec![], quotas);
    if cap.health() != capsule::CapsuleState::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_monitor_once_no_panic() -> TestResult {
    zerostate::monitor_once();
    TestResult::Pass
}

pub(crate) fn test_zerostate_monitor_once_multiple_calls() -> TestResult {
    zerostate::monitor_once();
    zerostate::monitor_once();
    zerostate::monitor_once();
    TestResult::Pass
}

pub(crate) fn test_zerostate_capsule_ids_increasing() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let cap1 = zerostate::register_capsule("increasing_id_1", alloc::vec![], quotas.clone());
    let cap2 = zerostate::register_capsule("increasing_id_2", alloc::vec![], quotas);
    if !(cap2.id.get() > cap1.id.get()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_register_with_empty_peers() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("empty_peers_cap", alloc::vec![], quotas);
    let peers = cap.peers.read();
    if !peers.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_register_with_many_peers() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let peers = alloc::vec!["p1", "p2", "p3", "p4", "p5"];
    let cap = zerostate::register_capsule("many_peers_cap", peers, quotas);
    let p = cap.peers.read();
    if p.len() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_capsule_name_preserved() -> TestResult {
    let quotas = capsule::CapsuleQuotas::default();
    let cap = zerostate::register_capsule("preserved_name", alloc::vec![], quotas);
    if cap.name != "preserved_name" {
        return TestResult::Fail;
    }
    let found = zerostate::get_capsule_by_name("preserved_name");
    if !found.is_some() {
        return TestResult::Fail;
    }
    if found.unwrap().name != "preserved_name" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_quotas_applied() -> TestResult {
    let quotas = capsule::CapsuleQuotas {
        inbox_capacity: 100,
        max_msg_bytes: 200,
        max_bytes_per_sec: 300,
        heartbeat_interval_ms: 400,
    };
    let cap = zerostate::register_capsule("quotas_applied_test", alloc::vec![], quotas);
    if cap.quotas.inbox_capacity != 100 {
        return TestResult::Fail;
    }
    if cap.quotas.max_msg_bytes != 200 {
        return TestResult::Fail;
    }
    if cap.quotas.max_bytes_per_sec != 300 {
        return TestResult::Fail;
    }
    if cap.quotas.heartbeat_interval_ms != 400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_stop_capsule_not_found() -> TestResult {
    let result = zerostate::stop_capsule("never_registered_stop");
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "capsule not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zerostate_start_capsule_not_found() -> TestResult {
    let token = crate::syscall::capabilities::CapabilityToken::empty();
    let result = zerostate::start_capsule("never_registered_start", &token);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "capsule not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
