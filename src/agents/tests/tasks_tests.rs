// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/tasks.rs

use crate::agents::tasks::{
    cancel_task, create_task, get_task, list_agent_tasks, pending_tasks, update_task_status,
    TaskStatus, MAX_TASKS,
};
use crate::test::framework::TestResult;

pub(crate) fn test_create_task() -> TestResult {
    let id = create_task(1, b"Test task");
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_create_task_unique_ids() -> TestResult {
    let id1 = create_task(1, b"Task 1");
    let id2 = create_task(1, b"Task 2");
    let id3 = create_task(2, b"Task 3");

    if id1 == id2 {
        return TestResult::Fail;
    }
    if id2 == id3 {
        return TestResult::Fail;
    }
    if id1 == id3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task() -> TestResult {
    let id = create_task(1, b"Get task test");
    let task = get_task(id);

    if task.is_none() {
        return TestResult::Fail;
    }
    let task = task.unwrap();
    if task.id != id {
        return TestResult::Fail;
    }
    if task.agent_id != 1 {
        return TestResult::Fail;
    }
    if task.description.as_slice() != b"Get task test" {
        return TestResult::Fail;
    }
    if task.status != TaskStatus::Pending {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_task_nonexistent() -> TestResult {
    let task = get_task(999999);
    if task.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_status_variants() -> TestResult {
    if TaskStatus::Pending != TaskStatus::Pending {
        return TestResult::Fail;
    }
    if TaskStatus::Running != TaskStatus::Running {
        return TestResult::Fail;
    }
    if TaskStatus::Complete != TaskStatus::Complete {
        return TestResult::Fail;
    }
    if TaskStatus::Failed != TaskStatus::Failed {
        return TestResult::Fail;
    }
    if TaskStatus::Cancelled != TaskStatus::Cancelled {
        return TestResult::Fail;
    }
    if TaskStatus::Pending == TaskStatus::Complete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_task_status_running() -> TestResult {
    let id = create_task(1, b"Status test");
    update_task_status(id, TaskStatus::Running, None);

    let task = get_task(id).unwrap();
    if task.status != TaskStatus::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_task_status_complete() -> TestResult {
    let id = create_task(1, b"Complete test");
    update_task_status(id, TaskStatus::Complete, Some(b"Result data"));

    let task = get_task(id).unwrap();
    if task.status != TaskStatus::Complete {
        return TestResult::Fail;
    }
    if task.result.as_slice() != b"Result data" {
        return TestResult::Fail;
    }
    if task.completed_at == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_task_status_failed() -> TestResult {
    let id = create_task(1, b"Fail test");
    update_task_status(id, TaskStatus::Failed, Some(b"Error message"));

    let task = get_task(id).unwrap();
    if task.status != TaskStatus::Failed {
        return TestResult::Fail;
    }
    if task.result.as_slice() != b"Error message" {
        return TestResult::Fail;
    }
    if task.completed_at == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_agent_tasks() -> TestResult {
    let agent_id = 5000;
    create_task(agent_id, b"Task A");
    create_task(agent_id, b"Task B");
    create_task(agent_id + 1, b"Other agent task");

    let tasks = list_agent_tasks(agent_id);
    if tasks.len() < 2 {
        return TestResult::Fail;
    }
    for task in &tasks {
        if task.agent_id != agent_id {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_list_agent_tasks_empty() -> TestResult {
    let tasks = list_agent_tasks(99999);
    if !tasks.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pending_tasks() -> TestResult {
    let agent_id = 6000;
    let id1 = create_task(agent_id, b"Pending 1");
    let id2 = create_task(agent_id, b"Pending 2");
    create_task(agent_id, b"Pending 3");

    update_task_status(id1, TaskStatus::Running, None);
    update_task_status(id2, TaskStatus::Complete, None);

    let pending = pending_tasks(agent_id);
    for task in &pending {
        if task.status != TaskStatus::Pending {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_cancel_task_pending() -> TestResult {
    let id = create_task(1, b"Cancel test");
    let result = cancel_task(id);

    if !result {
        return TestResult::Fail;
    }
    let task = get_task(id).unwrap();
    if task.status != TaskStatus::Cancelled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cancel_task_already_running() -> TestResult {
    let id = create_task(1, b"Running task");
    update_task_status(id, TaskStatus::Running, None);

    let result = cancel_task(id);
    if result {
        return TestResult::Fail;
    }

    let task = get_task(id).unwrap();
    if task.status != TaskStatus::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cancel_task_nonexistent() -> TestResult {
    let result = cancel_task(999999);
    if result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_timestamps() -> TestResult {
    let id = create_task(1, b"Timestamp test");
    let task = get_task(id).unwrap();

    if task.created_at == 0 {
        return TestResult::Fail;
    }
    if task.completed_at != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_clone() -> TestResult {
    let id = create_task(1, b"Clone test");
    let task = get_task(id).unwrap();
    let cloned = task.clone();

    if cloned.id != task.id {
        return TestResult::Fail;
    }
    if cloned.agent_id != task.agent_id {
        return TestResult::Fail;
    }
    if cloned.description != task.description {
        return TestResult::Fail;
    }
    if cloned.status != task.status {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_tasks_constant() -> TestResult {
    if MAX_TASKS != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_empty_description() -> TestResult {
    let id = create_task(1, b"");
    let task = get_task(id).unwrap();
    if !task.description.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_large_description() -> TestResult {
    let large_desc = [b'x'; 1000];
    let id = create_task(1, &large_desc);
    let task = get_task(id).unwrap();
    if task.description.len() != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_nonexistent_task() -> TestResult {
    update_task_status(999999, TaskStatus::Complete, Some(b"data"));
    TestResult::Pass
}

pub(crate) fn test_task_result_empty() -> TestResult {
    let id = create_task(1, b"No result");
    update_task_status(id, TaskStatus::Complete, None);

    let task = get_task(id).unwrap();
    if !task.result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_multiple_status_updates() -> TestResult {
    let id = create_task(1, b"Multi update");

    update_task_status(id, TaskStatus::Running, None);
    if get_task(id).unwrap().status != TaskStatus::Running {
        return TestResult::Fail;
    }

    update_task_status(id, TaskStatus::Complete, Some(b"Done"));
    let task = get_task(id).unwrap();
    if task.status != TaskStatus::Complete {
        return TestResult::Fail;
    }
    if task.result.as_slice() != b"Done" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
