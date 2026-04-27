// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/scheduler.rs

use crate::agents::scheduler::{
    active_count, cancel_schedule, list_scheduled, schedule_once, schedule_repeat, MAX_SCHEDULED,
};
use crate::test::framework::TestResult;

pub(crate) fn test_schedule_once() -> TestResult {
    let id = schedule_once(1, b"test prompt", 1000);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_once_unique_ids() -> TestResult {
    let id1 = schedule_once(1, b"prompt1", 1000);
    let id2 = schedule_once(1, b"prompt2", 2000);

    if id1 == id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_repeat() -> TestResult {
    let id = schedule_repeat(1, b"repeat prompt", 5000);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_repeat_unique_ids() -> TestResult {
    let id1 = schedule_repeat(1, b"prompt1", 1000);
    let id2 = schedule_repeat(1, b"prompt2", 2000);

    if id1 == id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cancel_schedule() -> TestResult {
    let id = schedule_once(1, b"cancel test", 100000);
    let result = cancel_schedule(id);
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cancel_schedule_nonexistent() -> TestResult {
    let result = cancel_schedule(999999);
    if result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cancel_schedule_already_cancelled() -> TestResult {
    let id = schedule_once(1, b"double cancel", 100000);
    cancel_schedule(id);
    let result = cancel_schedule(id);
    if result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_scheduled() -> TestResult {
    let agent_id = 7000;
    schedule_once(agent_id, b"list test 1", 100000);
    schedule_once(agent_id, b"list test 2", 100000);
    schedule_once(agent_id + 1, b"other agent", 100000);

    let scheduled = list_scheduled(agent_id);
    for s in &scheduled {
        if s.agent_id != agent_id {
            return TestResult::Fail;
        }
        if !s.active {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_list_scheduled_empty() -> TestResult {
    let scheduled = list_scheduled(99999);
    if !scheduled.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_scheduled_excludes_cancelled() -> TestResult {
    let agent_id = 8000;
    let id1 = schedule_once(agent_id, b"active", 100000);
    let id2 = schedule_once(agent_id, b"cancelled", 100000);

    cancel_schedule(id2);

    let scheduled = list_scheduled(agent_id);
    for s in &scheduled {
        if s.id == id2 {
            return TestResult::Fail;
        }
    }
    if !scheduled.iter().any(|s| s.id == id1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_active_count() -> TestResult {
    let before = active_count();
    schedule_once(1, b"count test", 100000);
    let after = active_count();
    if after < before {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_scheduled_constant() -> TestResult {
    if MAX_SCHEDULED != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduled_run_fields() -> TestResult {
    let agent_id = 9000;
    let run_at = 50000;
    schedule_once(agent_id, b"field test", run_at);

    let scheduled = list_scheduled(agent_id);
    if scheduled.is_empty() {
        return TestResult::Fail;
    }

    let s = &scheduled[0];
    if s.agent_id != agent_id {
        return TestResult::Fail;
    }
    if s.prompt.as_slice() != b"field test" {
        return TestResult::Fail;
    }
    if !s.active {
        return TestResult::Fail;
    }
    if s.repeat_interval != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduled_repeat_fields() -> TestResult {
    let agent_id = 9001;
    let interval = 5000;
    schedule_repeat(agent_id, b"repeat field test", interval);

    let scheduled = list_scheduled(agent_id);
    if scheduled.is_empty() {
        return TestResult::Fail;
    }

    let s = &scheduled[0];
    if s.agent_id != agent_id {
        return TestResult::Fail;
    }
    if s.repeat_interval != interval {
        return TestResult::Fail;
    }
    if !s.active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scheduled_clone() -> TestResult {
    let agent_id = 9002;
    schedule_once(agent_id, b"clone test", 100000);

    let scheduled = list_scheduled(agent_id);
    let original = &scheduled[0];
    let cloned = original.clone();

    if cloned.id != original.id {
        return TestResult::Fail;
    }
    if cloned.agent_id != original.agent_id {
        return TestResult::Fail;
    }
    if cloned.prompt != original.prompt {
        return TestResult::Fail;
    }
    if cloned.run_at != original.run_at {
        return TestResult::Fail;
    }
    if cloned.repeat_interval != original.repeat_interval {
        return TestResult::Fail;
    }
    if cloned.active != original.active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_empty_prompt() -> TestResult {
    let id = schedule_once(1, b"", 100000);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_large_prompt() -> TestResult {
    let large_prompt = [b'x'; 1000];
    let id = schedule_once(1, &large_prompt, 100000);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_zero_interval() -> TestResult {
    let id = schedule_repeat(1, b"zero interval", 0);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_schedule_large_interval() -> TestResult {
    let id = schedule_repeat(1, b"large interval", u64::MAX / 2);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixed_scheduling() -> TestResult {
    let agent_id = 9500;
    schedule_once(agent_id, b"once1", 100000);
    schedule_repeat(agent_id, b"repeat1", 5000);
    schedule_once(agent_id, b"once2", 200000);
    schedule_repeat(agent_id, b"repeat2", 10000);

    let scheduled = list_scheduled(agent_id);
    if scheduled.len() < 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
