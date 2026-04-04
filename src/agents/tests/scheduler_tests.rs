// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/scheduler.rs

use crate::agents::scheduler::{
    schedule_once, schedule_repeat, cancel_schedule, list_scheduled,
    active_count, MAX_SCHEDULED
};

#[test]
fn test_schedule_once() {
    let id = schedule_once(1, b"test prompt", 1000);
    assert!(id > 0);
}

#[test]
fn test_schedule_once_unique_ids() {
    let id1 = schedule_once(1, b"prompt1", 1000);
    let id2 = schedule_once(1, b"prompt2", 2000);

    assert_ne!(id1, id2);
}

#[test]
fn test_schedule_repeat() {
    let id = schedule_repeat(1, b"repeat prompt", 5000);
    assert!(id > 0);
}

#[test]
fn test_schedule_repeat_unique_ids() {
    let id1 = schedule_repeat(1, b"prompt1", 1000);
    let id2 = schedule_repeat(1, b"prompt2", 2000);

    assert_ne!(id1, id2);
}

#[test]
fn test_cancel_schedule() {
    let id = schedule_once(1, b"cancel test", 100000);
    let result = cancel_schedule(id);
    assert!(result);
}

#[test]
fn test_cancel_schedule_nonexistent() {
    let result = cancel_schedule(999999);
    assert!(!result);
}

#[test]
fn test_cancel_schedule_already_cancelled() {
    let id = schedule_once(1, b"double cancel", 100000);
    cancel_schedule(id);
    let result = cancel_schedule(id);
    assert!(!result);
}

#[test]
fn test_list_scheduled() {
    let agent_id = 7000;
    schedule_once(agent_id, b"list test 1", 100000);
    schedule_once(agent_id, b"list test 2", 100000);
    schedule_once(agent_id + 1, b"other agent", 100000);

    let scheduled = list_scheduled(agent_id);
    for s in &scheduled {
        assert_eq!(s.agent_id, agent_id);
        assert!(s.active);
    }
}

#[test]
fn test_list_scheduled_empty() {
    let scheduled = list_scheduled(99999);
    assert!(scheduled.is_empty());
}

#[test]
fn test_list_scheduled_excludes_cancelled() {
    let agent_id = 8000;
    let id1 = schedule_once(agent_id, b"active", 100000);
    let id2 = schedule_once(agent_id, b"cancelled", 100000);

    cancel_schedule(id2);

    let scheduled = list_scheduled(agent_id);
    for s in &scheduled {
        assert_ne!(s.id, id2);
    }
    assert!(scheduled.iter().any(|s| s.id == id1));
}

#[test]
fn test_active_count() {
    let before = active_count();
    schedule_once(1, b"count test", 100000);
    let after = active_count();
    assert!(after >= before);
}

#[test]
fn test_max_scheduled_constant() {
    assert_eq!(MAX_SCHEDULED, 32);
}

#[test]
fn test_scheduled_run_fields() {
    let agent_id = 9000;
    let run_at = 50000;
    schedule_once(agent_id, b"field test", run_at);

    let scheduled = list_scheduled(agent_id);
    assert!(!scheduled.is_empty());

    let s = &scheduled[0];
    assert_eq!(s.agent_id, agent_id);
    assert_eq!(s.prompt.as_slice(), b"field test");
    assert!(s.active);
    assert_eq!(s.repeat_interval, 0);
}

#[test]
fn test_scheduled_repeat_fields() {
    let agent_id = 9001;
    let interval = 5000;
    schedule_repeat(agent_id, b"repeat field test", interval);

    let scheduled = list_scheduled(agent_id);
    assert!(!scheduled.is_empty());

    let s = &scheduled[0];
    assert_eq!(s.agent_id, agent_id);
    assert_eq!(s.repeat_interval, interval);
    assert!(s.active);
}

#[test]
fn test_scheduled_clone() {
    let agent_id = 9002;
    schedule_once(agent_id, b"clone test", 100000);

    let scheduled = list_scheduled(agent_id);
    let original = &scheduled[0];
    let cloned = original.clone();

    assert_eq!(cloned.id, original.id);
    assert_eq!(cloned.agent_id, original.agent_id);
    assert_eq!(cloned.prompt, original.prompt);
    assert_eq!(cloned.run_at, original.run_at);
    assert_eq!(cloned.repeat_interval, original.repeat_interval);
    assert_eq!(cloned.active, original.active);
}

#[test]
fn test_schedule_empty_prompt() {
    let id = schedule_once(1, b"", 100000);
    assert!(id > 0);
}

#[test]
fn test_schedule_large_prompt() {
    let large_prompt = [b'x'; 1000];
    let id = schedule_once(1, &large_prompt, 100000);
    assert!(id > 0);
}

#[test]
fn test_schedule_zero_interval() {
    let id = schedule_repeat(1, b"zero interval", 0);
    assert!(id > 0);
}

#[test]
fn test_schedule_large_interval() {
    let id = schedule_repeat(1, b"large interval", u64::MAX / 2);
    assert!(id > 0);
}

#[test]
fn test_mixed_scheduling() {
    let agent_id = 9500;
    schedule_once(agent_id, b"once1", 100000);
    schedule_repeat(agent_id, b"repeat1", 5000);
    schedule_once(agent_id, b"once2", 200000);
    schedule_repeat(agent_id, b"repeat2", 10000);

    let scheduled = list_scheduled(agent_id);
    assert!(scheduled.len() >= 4);
}
