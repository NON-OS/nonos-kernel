// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::runtime::nonos_capsule::types::{CapsuleId, CapsuleState, CapsuleQuotas, next_capsule_id};

#[test]
fn test_capsule_id_get() {
    let id = CapsuleId(42);
    assert_eq!(id.get(), 42);
}

#[test]
fn test_capsule_id_get_zero() {
    let id = CapsuleId(0);
    assert_eq!(id.get(), 0);
}

#[test]
fn test_capsule_id_get_max() {
    let id = CapsuleId(u64::MAX);
    assert_eq!(id.get(), u64::MAX);
}

#[test]
fn test_capsule_id_equality() {
    let id1 = CapsuleId(100);
    let id2 = CapsuleId(100);
    let id3 = CapsuleId(200);
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

#[test]
fn test_capsule_id_ordering() {
    let id1 = CapsuleId(1);
    let id2 = CapsuleId(2);
    let id3 = CapsuleId(3);
    assert!(id1 < id2);
    assert!(id2 < id3);
    assert!(id1 < id3);
}

#[test]
fn test_capsule_id_ordering_equal() {
    let id1 = CapsuleId(50);
    let id2 = CapsuleId(50);
    assert!(id1 <= id2);
    assert!(id1 >= id2);
}

#[test]
fn test_capsule_id_clone() {
    let id1 = CapsuleId(123);
    let id2 = id1.clone();
    assert_eq!(id1, id2);
    assert_eq!(id1.get(), id2.get());
}

#[test]
fn test_capsule_id_copy() {
    let id1 = CapsuleId(456);
    let id2 = id1;
    assert_eq!(id1, id2);
}

#[test]
fn test_capsule_id_debug() {
    let id = CapsuleId(789);
    let debug_str = alloc::format!("{:?}", id);
    assert!(debug_str.contains("CapsuleId"));
    assert!(debug_str.contains("789"));
}

#[test]
fn test_capsule_id_partial_ord() {
    let id1 = CapsuleId(10);
    let id2 = CapsuleId(20);
    assert!(id1.partial_cmp(&id2) == Some(core::cmp::Ordering::Less));
}

#[test]
fn test_capsule_id_ord() {
    let id1 = CapsuleId(5);
    let id2 = CapsuleId(10);
    assert_eq!(id1.cmp(&id2), core::cmp::Ordering::Less);
    assert_eq!(id2.cmp(&id1), core::cmp::Ordering::Greater);
    assert_eq!(id1.cmp(&id1), core::cmp::Ordering::Equal);
}

#[test]
fn test_next_capsule_id_increments() {
    let id1 = next_capsule_id();
    let id2 = next_capsule_id();
    let id3 = next_capsule_id();
    assert!(id1.get() < id2.get());
    assert!(id2.get() < id3.get());
}

#[test]
fn test_next_capsule_id_unique() {
    let id1 = next_capsule_id();
    let id2 = next_capsule_id();
    assert_ne!(id1, id2);
}

#[test]
fn test_capsule_state_stopped() {
    let state = CapsuleState::Stopped;
    assert_eq!(state, CapsuleState::Stopped);
}

#[test]
fn test_capsule_state_running() {
    let state = CapsuleState::Running;
    assert_eq!(state, CapsuleState::Running);
}

#[test]
fn test_capsule_state_degraded() {
    let state = CapsuleState::Degraded;
    assert_eq!(state, CapsuleState::Degraded);
}

#[test]
fn test_capsule_state_equality() {
    assert_eq!(CapsuleState::Stopped, CapsuleState::Stopped);
    assert_eq!(CapsuleState::Running, CapsuleState::Running);
    assert_eq!(CapsuleState::Degraded, CapsuleState::Degraded);
}

#[test]
fn test_capsule_state_inequality() {
    assert_ne!(CapsuleState::Stopped, CapsuleState::Running);
    assert_ne!(CapsuleState::Running, CapsuleState::Degraded);
    assert_ne!(CapsuleState::Stopped, CapsuleState::Degraded);
}

#[test]
fn test_capsule_state_clone() {
    let state = CapsuleState::Running;
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
fn test_capsule_state_copy() {
    let state1 = CapsuleState::Degraded;
    let state2 = state1;
    assert_eq!(state1, state2);
}

#[test]
fn test_capsule_state_debug() {
    let state = CapsuleState::Running;
    let debug_str = alloc::format!("{:?}", state);
    assert!(debug_str.contains("Running"));
}

#[test]
fn test_capsule_state_all_variants_debug() {
    let stopped = alloc::format!("{:?}", CapsuleState::Stopped);
    let running = alloc::format!("{:?}", CapsuleState::Running);
    let degraded = alloc::format!("{:?}", CapsuleState::Degraded);
    assert!(stopped.contains("Stopped"));
    assert!(running.contains("Running"));
    assert!(degraded.contains("Degraded"));
}

#[test]
fn test_capsule_quotas_default() {
    let quotas = CapsuleQuotas::default();
    assert_eq!(quotas.inbox_capacity, 1024);
    assert_eq!(quotas.max_msg_bytes, 1 << 20);
    assert_eq!(quotas.max_bytes_per_sec, 4 << 20);
    assert_eq!(quotas.heartbeat_interval_ms, 2_000);
}

#[test]
fn test_capsule_quotas_default_inbox_capacity() {
    let quotas = CapsuleQuotas::default();
    assert_eq!(quotas.inbox_capacity, 1024);
}

#[test]
fn test_capsule_quotas_default_max_msg_bytes() {
    let quotas = CapsuleQuotas::default();
    assert_eq!(quotas.max_msg_bytes, 1024 * 1024);
}

#[test]
fn test_capsule_quotas_default_max_bytes_per_sec() {
    let quotas = CapsuleQuotas::default();
    assert_eq!(quotas.max_bytes_per_sec, 4 * 1024 * 1024);
}

#[test]
fn test_capsule_quotas_default_heartbeat_interval() {
    let quotas = CapsuleQuotas::default();
    assert_eq!(quotas.heartbeat_interval_ms, 2000);
}

#[test]
fn test_capsule_quotas_custom() {
    let quotas = CapsuleQuotas {
        inbox_capacity: 512,
        max_msg_bytes: 4096,
        max_bytes_per_sec: 1024,
        heartbeat_interval_ms: 5000,
    };
    assert_eq!(quotas.inbox_capacity, 512);
    assert_eq!(quotas.max_msg_bytes, 4096);
    assert_eq!(quotas.max_bytes_per_sec, 1024);
    assert_eq!(quotas.heartbeat_interval_ms, 5000);
}

#[test]
fn test_capsule_quotas_clone() {
    let quotas1 = CapsuleQuotas {
        inbox_capacity: 256,
        max_msg_bytes: 2048,
        max_bytes_per_sec: 512,
        heartbeat_interval_ms: 1000,
    };
    let quotas2 = quotas1.clone();
    assert_eq!(quotas1.inbox_capacity, quotas2.inbox_capacity);
    assert_eq!(quotas1.max_msg_bytes, quotas2.max_msg_bytes);
    assert_eq!(quotas1.max_bytes_per_sec, quotas2.max_bytes_per_sec);
    assert_eq!(quotas1.heartbeat_interval_ms, quotas2.heartbeat_interval_ms);
}

#[test]
fn test_capsule_quotas_debug() {
    let quotas = CapsuleQuotas::default();
    let debug_str = alloc::format!("{:?}", quotas);
    assert!(debug_str.contains("CapsuleQuotas"));
    assert!(debug_str.contains("inbox_capacity"));
}

#[test]
fn test_capsule_quotas_zero_values() {
    let quotas = CapsuleQuotas {
        inbox_capacity: 0,
        max_msg_bytes: 0,
        max_bytes_per_sec: 0,
        heartbeat_interval_ms: 0,
    };
    assert_eq!(quotas.inbox_capacity, 0);
    assert_eq!(quotas.max_msg_bytes, 0);
    assert_eq!(quotas.max_bytes_per_sec, 0);
    assert_eq!(quotas.heartbeat_interval_ms, 0);
}

#[test]
fn test_capsule_quotas_max_values() {
    let quotas = CapsuleQuotas {
        inbox_capacity: usize::MAX,
        max_msg_bytes: usize::MAX,
        max_bytes_per_sec: u64::MAX,
        heartbeat_interval_ms: u64::MAX,
    };
    assert_eq!(quotas.inbox_capacity, usize::MAX);
    assert_eq!(quotas.max_msg_bytes, usize::MAX);
    assert_eq!(quotas.max_bytes_per_sec, u64::MAX);
    assert_eq!(quotas.heartbeat_interval_ms, u64::MAX);
}

#[test]
fn test_capsule_quotas_inbox_capacity_power_of_two() {
    let quotas = CapsuleQuotas::default();
    assert!((quotas.inbox_capacity & (quotas.inbox_capacity - 1)) == 0);
}

#[test]
fn test_capsule_quotas_max_msg_bytes_power_of_two() {
    let quotas = CapsuleQuotas::default();
    assert!((quotas.max_msg_bytes & (quotas.max_msg_bytes - 1)) == 0);
}

#[test]
fn test_capsule_quotas_max_bytes_per_sec_power_of_two() {
    let quotas = CapsuleQuotas::default();
    assert!((quotas.max_bytes_per_sec & (quotas.max_bytes_per_sec - 1)) == 0);
}

#[test]
fn test_capsule_state_all_variants() {
    let states = [
        CapsuleState::Stopped,
        CapsuleState::Running,
        CapsuleState::Degraded,
    ];
    for state in states {
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }
}

#[test]
fn test_capsule_id_size() {
    assert_eq!(core::mem::size_of::<CapsuleId>(), 8);
}

#[test]
fn test_capsule_state_size() {
    assert!(core::mem::size_of::<CapsuleState>() <= 1);
}

#[test]
fn test_capsule_quotas_size() {
    assert_eq!(core::mem::size_of::<CapsuleQuotas>(), 32);
}

#[test]
fn test_capsule_id_alignment() {
    assert_eq!(core::mem::align_of::<CapsuleId>(), 8);
}

#[test]
fn test_capsule_quotas_alignment() {
    assert_eq!(core::mem::align_of::<CapsuleQuotas>(), 8);
}

#[test]
fn test_capsule_id_min_max_ordering() {
    let min = CapsuleId(0);
    let max = CapsuleId(u64::MAX);
    assert!(min < max);
    assert!(max > min);
}

#[test]
fn test_capsule_quotas_heartbeat_reasonable() {
    let quotas = CapsuleQuotas::default();
    assert!(quotas.heartbeat_interval_ms >= 1000);
    assert!(quotas.heartbeat_interval_ms <= 10_000);
}

#[test]
fn test_capsule_quotas_inbox_reasonable() {
    let quotas = CapsuleQuotas::default();
    assert!(quotas.inbox_capacity >= 64);
    assert!(quotas.inbox_capacity <= 65536);
}

#[test]
fn test_capsule_quotas_msg_bytes_reasonable() {
    let quotas = CapsuleQuotas::default();
    assert!(quotas.max_msg_bytes >= 1024);
    assert!(quotas.max_msg_bytes <= 16 * 1024 * 1024);
}

#[test]
fn test_capsule_quotas_bytes_per_sec_reasonable() {
    let quotas = CapsuleQuotas::default();
    assert!(quotas.max_bytes_per_sec >= 1024);
    assert!(quotas.max_bytes_per_sec <= 1024 * 1024 * 1024);
}

#[test]
fn test_next_capsule_id_nonzero() {
    let id = next_capsule_id();
    assert!(id.get() > 0);
}

#[test]
fn test_capsule_id_from_sequential() {
    let id1 = CapsuleId(1);
    let id2 = CapsuleId(2);
    let id3 = CapsuleId(3);
    assert_eq!(id2.get() - id1.get(), 1);
    assert_eq!(id3.get() - id2.get(), 1);
}

#[test]
fn test_capsule_quotas_multiple_defaults() {
    let q1 = CapsuleQuotas::default();
    let q2 = CapsuleQuotas::default();
    assert_eq!(q1.inbox_capacity, q2.inbox_capacity);
    assert_eq!(q1.max_msg_bytes, q2.max_msg_bytes);
    assert_eq!(q1.max_bytes_per_sec, q2.max_bytes_per_sec);
    assert_eq!(q1.heartbeat_interval_ms, q2.heartbeat_interval_ms);
}

#[test]
fn test_capsule_state_stopped_not_running() {
    let state = CapsuleState::Stopped;
    assert_ne!(state, CapsuleState::Running);
    assert_ne!(state, CapsuleState::Degraded);
}

#[test]
fn test_capsule_state_running_not_stopped() {
    let state = CapsuleState::Running;
    assert_ne!(state, CapsuleState::Stopped);
    assert_ne!(state, CapsuleState::Degraded);
}

#[test]
fn test_capsule_state_degraded_not_others() {
    let state = CapsuleState::Degraded;
    assert_ne!(state, CapsuleState::Stopped);
    assert_ne!(state, CapsuleState::Running);
}

#[test]
fn test_capsule_id_hash_eq_consistency() {
    let id1 = CapsuleId(42);
    let id2 = CapsuleId(42);
    assert_eq!(id1, id2);
}

#[test]
fn test_capsule_quotas_clone_independence() {
    let original = CapsuleQuotas {
        inbox_capacity: 100,
        max_msg_bytes: 200,
        max_bytes_per_sec: 300,
        heartbeat_interval_ms: 400,
    };
    let mut cloned = original.clone();
    cloned.inbox_capacity = 999;
    assert_eq!(original.inbox_capacity, 100);
    assert_eq!(cloned.inbox_capacity, 999);
}

