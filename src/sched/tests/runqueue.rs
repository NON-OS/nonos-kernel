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

use crate::sched::*;

fn dummy_fn() {}

fn create_task(id: u64) -> Task {
    let mut task = Task::spawn("test", dummy_fn, Priority::Normal, CpuAffinity::any());
    task.id = id;
    task
}

#[test]
fn test_runqueue_new() {
    let rq = RunQueue::new();
    assert!(rq.is_empty());
    assert_eq!(rq.len(), 0);
}

#[test]
fn test_runqueue_push_single() {
    let mut rq = RunQueue::new();
    let task = create_task(1);
    rq.push(task);
    assert_eq!(rq.len(), 1);
    assert!(!rq.is_empty());
}

#[test]
fn test_runqueue_push_multiple() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));
    assert_eq!(rq.len(), 3);
}

#[test]
fn test_runqueue_pop_empty() {
    let mut rq = RunQueue::new();
    assert!(rq.pop().is_none());
}

#[test]
fn test_runqueue_pop_single() {
    let mut rq = RunQueue::new();
    rq.push(create_task(42));
    let popped = rq.pop();
    assert!(popped.is_some());
    assert_eq!(popped.unwrap().id, 42);
    assert!(rq.is_empty());
}

#[test]
fn test_runqueue_fifo_order() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    assert_eq!(rq.pop().unwrap().id, 1);
    assert_eq!(rq.pop().unwrap().id, 2);
    assert_eq!(rq.pop().unwrap().id, 3);
    assert!(rq.pop().is_none());
}

#[test]
fn test_runqueue_clear() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));
    rq.clear();
    assert!(rq.is_empty());
    assert_eq!(rq.len(), 0);
}

#[test]
fn test_runqueue_clear_empty() {
    let mut rq = RunQueue::new();
    rq.clear();
    assert!(rq.is_empty());
}

#[test]
fn test_runqueue_is_empty_after_pop() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.pop();
    assert!(rq.is_empty());
}

#[test]
fn test_runqueue_len_after_operations() {
    let mut rq = RunQueue::new();
    assert_eq!(rq.len(), 0);
    rq.push(create_task(1));
    assert_eq!(rq.len(), 1);
    rq.push(create_task(2));
    assert_eq!(rq.len(), 2);
    rq.pop();
    assert_eq!(rq.len(), 1);
    rq.pop();
    assert_eq!(rq.len(), 0);
}

#[test]
fn test_runqueue_remove_by_id_existing() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    let removed = rq.remove_by_id(2);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, 2);
    assert_eq!(rq.len(), 2);
}

#[test]
fn test_runqueue_remove_by_id_nonexistent() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));

    let removed = rq.remove_by_id(999);
    assert!(removed.is_none());
    assert_eq!(rq.len(), 2);
}

#[test]
fn test_runqueue_remove_by_id_empty() {
    let mut rq = RunQueue::new();
    let removed = rq.remove_by_id(1);
    assert!(removed.is_none());
}

#[test]
fn test_runqueue_remove_by_id_first() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    let removed = rq.remove_by_id(1);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, 1);
    assert_eq!(rq.pop().unwrap().id, 2);
}

#[test]
fn test_runqueue_remove_by_id_last() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    let removed = rq.remove_by_id(3);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, 3);
    assert_eq!(rq.len(), 2);
}

#[test]
fn test_runqueue_remove_by_id_maintains_order() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));
    rq.push(create_task(4));
    rq.push(create_task(5));

    rq.remove_by_id(3);

    assert_eq!(rq.pop().unwrap().id, 1);
    assert_eq!(rq.pop().unwrap().id, 2);
    assert_eq!(rq.pop().unwrap().id, 4);
    assert_eq!(rq.pop().unwrap().id, 5);
}

#[test]
fn test_runqueue_mixed_operations() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.pop();
    rq.push(create_task(3));
    rq.remove_by_id(2);
    rq.push(create_task(4));

    assert_eq!(rq.len(), 2);
    assert_eq!(rq.pop().unwrap().id, 3);
    assert_eq!(rq.pop().unwrap().id, 4);
}

#[test]
fn test_runqueue_push_after_clear() {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.clear();
    rq.push(create_task(3));

    assert_eq!(rq.len(), 1);
    assert_eq!(rq.pop().unwrap().id, 3);
}

#[test]
fn test_runqueue_large_number_of_tasks() {
    let mut rq = RunQueue::new();
    for i in 0..100 {
        rq.push(create_task(i));
    }
    assert_eq!(rq.len(), 100);

    for i in 0..100 {
        let task = rq.pop().unwrap();
        assert_eq!(task.id, i);
    }
    assert!(rq.is_empty());
}
