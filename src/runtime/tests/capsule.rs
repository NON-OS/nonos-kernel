// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::runtime::nonos_capsule::types::{
    next_capsule_id, CapsuleId, CapsuleQuotas, CapsuleState,
};
use crate::test::framework::TestResult;

pub(crate) fn test_capsule_id_get() -> TestResult {
    let id = CapsuleId(42);
    if id.get() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_get_zero() -> TestResult {
    let id = CapsuleId(0);
    if id.get() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_get_max() -> TestResult {
    let id = CapsuleId(u64::MAX);
    if id.get() != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_equality() -> TestResult {
    let id1 = CapsuleId(100);
    let id2 = CapsuleId(100);
    let id3 = CapsuleId(200);
    if id1 != id2 {
        return TestResult::Fail;
    }
    if id1 == id3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_ordering() -> TestResult {
    let id1 = CapsuleId(1);
    let id2 = CapsuleId(2);
    let id3 = CapsuleId(3);
    if !(id1 < id2) {
        return TestResult::Fail;
    }
    if !(id2 < id3) {
        return TestResult::Fail;
    }
    if !(id1 < id3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_ordering_equal() -> TestResult {
    let id1 = CapsuleId(50);
    let id2 = CapsuleId(50);
    if !(id1 <= id2) {
        return TestResult::Fail;
    }
    if !(id1 >= id2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_clone() -> TestResult {
    let id1 = CapsuleId(123);
    let id2 = id1.clone();
    if id1 != id2 {
        return TestResult::Fail;
    }
    if id1.get() != id2.get() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_copy() -> TestResult {
    let id1 = CapsuleId(456);
    let id2 = id1;
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_debug() -> TestResult {
    let id = CapsuleId(789);
    let debug_str = alloc::format!("{:?}", id);
    if !debug_str.contains("CapsuleId") {
        return TestResult::Fail;
    }
    if !debug_str.contains("789") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_partial_ord() -> TestResult {
    let id1 = CapsuleId(10);
    let id2 = CapsuleId(20);
    if !(id1.partial_cmp(&id2) == Some(core::cmp::Ordering::Less)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_ord() -> TestResult {
    let id1 = CapsuleId(5);
    let id2 = CapsuleId(10);
    if id1.cmp(&id2) != core::cmp::Ordering::Less {
        return TestResult::Fail;
    }
    if id2.cmp(&id1) != core::cmp::Ordering::Greater {
        return TestResult::Fail;
    }
    if id1.cmp(&id1) != core::cmp::Ordering::Equal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_next_capsule_id_increments() -> TestResult {
    let id1 = next_capsule_id();
    let id2 = next_capsule_id();
    let id3 = next_capsule_id();
    if !(id1.get() < id2.get()) {
        return TestResult::Fail;
    }
    if !(id2.get() < id3.get()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_next_capsule_id_unique() -> TestResult {
    let id1 = next_capsule_id();
    let id2 = next_capsule_id();
    if id1 == id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_stopped() -> TestResult {
    let state = CapsuleState::Stopped;
    if state != CapsuleState::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_running() -> TestResult {
    let state = CapsuleState::Running;
    if state != CapsuleState::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_degraded() -> TestResult {
    let state = CapsuleState::Degraded;
    if state != CapsuleState::Degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_equality() -> TestResult {
    if CapsuleState::Stopped != CapsuleState::Stopped {
        return TestResult::Fail;
    }
    if CapsuleState::Running != CapsuleState::Running {
        return TestResult::Fail;
    }
    if CapsuleState::Degraded != CapsuleState::Degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_inequality() -> TestResult {
    if CapsuleState::Stopped == CapsuleState::Running {
        return TestResult::Fail;
    }
    if CapsuleState::Running == CapsuleState::Degraded {
        return TestResult::Fail;
    }
    if CapsuleState::Stopped == CapsuleState::Degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_clone() -> TestResult {
    let state = CapsuleState::Running;
    let cloned = state.clone();
    if state != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_copy() -> TestResult {
    let state1 = CapsuleState::Degraded;
    let state2 = state1;
    if state1 != state2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_debug() -> TestResult {
    let state = CapsuleState::Running;
    let debug_str = alloc::format!("{:?}", state);
    if !debug_str.contains("Running") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_all_variants_debug() -> TestResult {
    let stopped = alloc::format!("{:?}", CapsuleState::Stopped);
    let running = alloc::format!("{:?}", CapsuleState::Running);
    let degraded = alloc::format!("{:?}", CapsuleState::Degraded);
    if !stopped.contains("Stopped") {
        return TestResult::Fail;
    }
    if !running.contains("Running") {
        return TestResult::Fail;
    }
    if !degraded.contains("Degraded") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_default() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if quotas.inbox_capacity != 1024 {
        return TestResult::Fail;
    }
    if quotas.max_msg_bytes != 1 << 20 {
        return TestResult::Fail;
    }
    if quotas.max_bytes_per_sec != 4 << 20 {
        return TestResult::Fail;
    }
    if quotas.heartbeat_interval_ms != 2_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_default_inbox_capacity() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if quotas.inbox_capacity != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_default_max_msg_bytes() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if quotas.max_msg_bytes != 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_default_max_bytes_per_sec() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if quotas.max_bytes_per_sec != 4 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_default_heartbeat_interval() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if quotas.heartbeat_interval_ms != 2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_custom() -> TestResult {
    let quotas = CapsuleQuotas {
        inbox_capacity: 512,
        max_msg_bytes: 4096,
        max_bytes_per_sec: 1024,
        heartbeat_interval_ms: 5000,
    };
    if quotas.inbox_capacity != 512 {
        return TestResult::Fail;
    }
    if quotas.max_msg_bytes != 4096 {
        return TestResult::Fail;
    }
    if quotas.max_bytes_per_sec != 1024 {
        return TestResult::Fail;
    }
    if quotas.heartbeat_interval_ms != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_clone() -> TestResult {
    let quotas1 = CapsuleQuotas {
        inbox_capacity: 256,
        max_msg_bytes: 2048,
        max_bytes_per_sec: 512,
        heartbeat_interval_ms: 1000,
    };
    let quotas2 = quotas1.clone();
    if quotas1.inbox_capacity != quotas2.inbox_capacity {
        return TestResult::Fail;
    }
    if quotas1.max_msg_bytes != quotas2.max_msg_bytes {
        return TestResult::Fail;
    }
    if quotas1.max_bytes_per_sec != quotas2.max_bytes_per_sec {
        return TestResult::Fail;
    }
    if quotas1.heartbeat_interval_ms != quotas2.heartbeat_interval_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_debug() -> TestResult {
    let quotas = CapsuleQuotas::default();
    let debug_str = alloc::format!("{:?}", quotas);
    if !debug_str.contains("CapsuleQuotas") {
        return TestResult::Fail;
    }
    if !debug_str.contains("inbox_capacity") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_zero_values() -> TestResult {
    let quotas = CapsuleQuotas {
        inbox_capacity: 0,
        max_msg_bytes: 0,
        max_bytes_per_sec: 0,
        heartbeat_interval_ms: 0,
    };
    if quotas.inbox_capacity != 0 {
        return TestResult::Fail;
    }
    if quotas.max_msg_bytes != 0 {
        return TestResult::Fail;
    }
    if quotas.max_bytes_per_sec != 0 {
        return TestResult::Fail;
    }
    if quotas.heartbeat_interval_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_max_values() -> TestResult {
    let quotas = CapsuleQuotas {
        inbox_capacity: usize::MAX,
        max_msg_bytes: usize::MAX,
        max_bytes_per_sec: u64::MAX,
        heartbeat_interval_ms: u64::MAX,
    };
    if quotas.inbox_capacity != usize::MAX {
        return TestResult::Fail;
    }
    if quotas.max_msg_bytes != usize::MAX {
        return TestResult::Fail;
    }
    if quotas.max_bytes_per_sec != u64::MAX {
        return TestResult::Fail;
    }
    if quotas.heartbeat_interval_ms != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_inbox_capacity_power_of_two() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !((quotas.inbox_capacity & (quotas.inbox_capacity - 1)) == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_max_msg_bytes_power_of_two() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !((quotas.max_msg_bytes & (quotas.max_msg_bytes - 1)) == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_max_bytes_per_sec_power_of_two() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !((quotas.max_bytes_per_sec & (quotas.max_bytes_per_sec - 1)) == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_all_variants() -> TestResult {
    let states = [CapsuleState::Stopped, CapsuleState::Running, CapsuleState::Degraded];
    for state in states {
        let cloned = state.clone();
        if state != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_size() -> TestResult {
    if core::mem::size_of::<CapsuleId>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_size() -> TestResult {
    if !(core::mem::size_of::<CapsuleState>() <= 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_size() -> TestResult {
    if core::mem::size_of::<CapsuleQuotas>() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_alignment() -> TestResult {
    if core::mem::align_of::<CapsuleId>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_alignment() -> TestResult {
    if core::mem::align_of::<CapsuleQuotas>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_min_max_ordering() -> TestResult {
    let min = CapsuleId(0);
    let max = CapsuleId(u64::MAX);
    if !(min < max) {
        return TestResult::Fail;
    }
    if !(max > min) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_heartbeat_reasonable() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !(quotas.heartbeat_interval_ms >= 1000) {
        return TestResult::Fail;
    }
    if !(quotas.heartbeat_interval_ms <= 10_000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_inbox_reasonable() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !(quotas.inbox_capacity >= 64) {
        return TestResult::Fail;
    }
    if !(quotas.inbox_capacity <= 65536) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_msg_bytes_reasonable() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !(quotas.max_msg_bytes >= 1024) {
        return TestResult::Fail;
    }
    if !(quotas.max_msg_bytes <= 16 * 1024 * 1024) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_bytes_per_sec_reasonable() -> TestResult {
    let quotas = CapsuleQuotas::default();
    if !(quotas.max_bytes_per_sec >= 1024) {
        return TestResult::Fail;
    }
    if !(quotas.max_bytes_per_sec <= 1024 * 1024 * 1024) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_next_capsule_id_nonzero() -> TestResult {
    let id = next_capsule_id();
    if !(id.get() > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_from_sequential() -> TestResult {
    let id1 = CapsuleId(1);
    let id2 = CapsuleId(2);
    let id3 = CapsuleId(3);
    if id2.get() - id1.get() != 1 {
        return TestResult::Fail;
    }
    if id3.get() - id2.get() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_multiple_defaults() -> TestResult {
    let q1 = CapsuleQuotas::default();
    let q2 = CapsuleQuotas::default();
    if q1.inbox_capacity != q2.inbox_capacity {
        return TestResult::Fail;
    }
    if q1.max_msg_bytes != q2.max_msg_bytes {
        return TestResult::Fail;
    }
    if q1.max_bytes_per_sec != q2.max_bytes_per_sec {
        return TestResult::Fail;
    }
    if q1.heartbeat_interval_ms != q2.heartbeat_interval_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_stopped_not_running() -> TestResult {
    let state = CapsuleState::Stopped;
    if state == CapsuleState::Running {
        return TestResult::Fail;
    }
    if state == CapsuleState::Degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_running_not_stopped() -> TestResult {
    let state = CapsuleState::Running;
    if state == CapsuleState::Stopped {
        return TestResult::Fail;
    }
    if state == CapsuleState::Degraded {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_state_degraded_not_others() -> TestResult {
    let state = CapsuleState::Degraded;
    if state == CapsuleState::Stopped {
        return TestResult::Fail;
    }
    if state == CapsuleState::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_id_hash_eq_consistency() -> TestResult {
    let id1 = CapsuleId(42);
    let id2 = CapsuleId(42);
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_quotas_clone_independence() -> TestResult {
    let original = CapsuleQuotas {
        inbox_capacity: 100,
        max_msg_bytes: 200,
        max_bytes_per_sec: 300,
        heartbeat_interval_ms: 400,
    };
    let mut cloned = original.clone();
    cloned.inbox_capacity = 999;
    if original.inbox_capacity != 100 {
        return TestResult::Fail;
    }
    if cloned.inbox_capacity != 999 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
