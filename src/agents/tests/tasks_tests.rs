// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/tasks.rs

use crate::agents::tasks::{
    create_task, update_task_status, get_task, list_agent_tasks,
    pending_tasks, cancel_task, TaskStatus, MAX_TASKS
};

#[test_case]
fn test_create_task() {
    let id = create_task(1, b"Test task");
    assert!(id > 0);
}

#[test_case]
fn test_create_task_unique_ids() {
    let id1 = create_task(1, b"Task 1");
    let id2 = create_task(1, b"Task 2");
    let id3 = create_task(2, b"Task 3");

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

#[test_case]
fn test_get_task() {
    let id = create_task(1, b"Get task test");
    let task = get_task(id);

    assert!(task.is_some());
    let task = task.unwrap();
    assert_eq!(task.id, id);
    assert_eq!(task.agent_id, 1);
    assert_eq!(task.description.as_slice(), b"Get task test");
    assert_eq!(task.status, TaskStatus::Pending);
}

#[test_case]
fn test_get_task_nonexistent() {
    let task = get_task(999999);
    assert!(task.is_none());
}

#[test_case]
fn test_task_status_variants() {
    assert_eq!(TaskStatus::Pending, TaskStatus::Pending);
    assert_eq!(TaskStatus::Running, TaskStatus::Running);
    assert_eq!(TaskStatus::Complete, TaskStatus::Complete);
    assert_eq!(TaskStatus::Failed, TaskStatus::Failed);
    assert_eq!(TaskStatus::Cancelled, TaskStatus::Cancelled);
    assert_ne!(TaskStatus::Pending, TaskStatus::Complete);
}

#[test_case]
fn test_update_task_status_running() {
    let id = create_task(1, b"Status test");
    update_task_status(id, TaskStatus::Running, None);

    let task = get_task(id).unwrap();
    assert_eq!(task.status, TaskStatus::Running);
}

#[test_case]
fn test_update_task_status_complete() {
    let id = create_task(1, b"Complete test");
    update_task_status(id, TaskStatus::Complete, Some(b"Result data"));

    let task = get_task(id).unwrap();
    assert_eq!(task.status, TaskStatus::Complete);
    assert_eq!(task.result.as_slice(), b"Result data");
    assert!(task.completed_at > 0);
}

#[test_case]
fn test_update_task_status_failed() {
    let id = create_task(1, b"Fail test");
    update_task_status(id, TaskStatus::Failed, Some(b"Error message"));

    let task = get_task(id).unwrap();
    assert_eq!(task.status, TaskStatus::Failed);
    assert_eq!(task.result.as_slice(), b"Error message");
    assert!(task.completed_at > 0);
}

#[test_case]
fn test_list_agent_tasks() {
    let agent_id = 5000;
    create_task(agent_id, b"Task A");
    create_task(agent_id, b"Task B");
    create_task(agent_id + 1, b"Other agent task");

    let tasks = list_agent_tasks(agent_id);
    assert!(tasks.len() >= 2);
    for task in &tasks {
        assert_eq!(task.agent_id, agent_id);
    }
}

#[test_case]
fn test_list_agent_tasks_empty() {
    let tasks = list_agent_tasks(99999);
    assert!(tasks.is_empty());
}

#[test_case]
fn test_pending_tasks() {
    let agent_id = 6000;
    let id1 = create_task(agent_id, b"Pending 1");
    let id2 = create_task(agent_id, b"Pending 2");
    create_task(agent_id, b"Pending 3");

    update_task_status(id1, TaskStatus::Running, None);
    update_task_status(id2, TaskStatus::Complete, None);

    let pending = pending_tasks(agent_id);
    for task in &pending {
        assert_eq!(task.status, TaskStatus::Pending);
    }
}

#[test_case]
fn test_cancel_task_pending() {
    let id = create_task(1, b"Cancel test");
    let result = cancel_task(id);

    assert!(result);
    let task = get_task(id).unwrap();
    assert_eq!(task.status, TaskStatus::Cancelled);
}

#[test_case]
fn test_cancel_task_already_running() {
    let id = create_task(1, b"Running task");
    update_task_status(id, TaskStatus::Running, None);

    let result = cancel_task(id);
    assert!(!result);

    let task = get_task(id).unwrap();
    assert_eq!(task.status, TaskStatus::Running);
}

#[test_case]
fn test_cancel_task_nonexistent() {
    let result = cancel_task(999999);
    assert!(!result);
}

#[test_case]
fn test_task_timestamps() {
    let id = create_task(1, b"Timestamp test");
    let task = get_task(id).unwrap();

    assert!(task.created_at > 0);
    assert_eq!(task.completed_at, 0);
}

#[test_case]
fn test_task_clone() {
    let id = create_task(1, b"Clone test");
    let task = get_task(id).unwrap();
    let cloned = task.clone();

    assert_eq!(cloned.id, task.id);
    assert_eq!(cloned.agent_id, task.agent_id);
    assert_eq!(cloned.description, task.description);
    assert_eq!(cloned.status, task.status);
}

#[test_case]
fn test_max_tasks_constant() {
    assert_eq!(MAX_TASKS, 64);
}

#[test_case]
fn test_task_empty_description() {
    let id = create_task(1, b"");
    let task = get_task(id).unwrap();
    assert!(task.description.is_empty());
}

#[test_case]
fn test_task_large_description() {
    let large_desc = [b'x'; 1000];
    let id = create_task(1, &large_desc);
    let task = get_task(id).unwrap();
    assert_eq!(task.description.len(), 1000);
}

#[test_case]
fn test_update_nonexistent_task() {
    update_task_status(999999, TaskStatus::Complete, Some(b"data"));
}

#[test_case]
fn test_task_result_empty() {
    let id = create_task(1, b"No result");
    update_task_status(id, TaskStatus::Complete, None);

    let task = get_task(id).unwrap();
    assert!(task.result.is_empty());
}

#[test_case]
fn test_task_multiple_status_updates() {
    let id = create_task(1, b"Multi update");

    update_task_status(id, TaskStatus::Running, None);
    assert_eq!(get_task(id).unwrap().status, TaskStatus::Running);

    update_task_status(id, TaskStatus::Complete, Some(b"Done"));
    let task = get_task(id).unwrap();
    assert_eq!(task.status, TaskStatus::Complete);
    assert_eq!(task.result.as_slice(), b"Done");
}
