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
use crate::test::framework::TestResult;

fn dummy_fn() {}

fn create_task(id: u64) -> Task {
    let mut task = Task::spawn("test", dummy_fn, Priority::Normal, CpuAffinity::any());
    task.id = id;
    task
}

pub(crate) fn test_runqueue_new() -> TestResult {
    let rq = RunQueue::new();
    if !rq.is_empty() {
        return TestResult::Fail;
    }
    if rq.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_push_single() -> TestResult {
    let mut rq = RunQueue::new();
    let task = create_task(1);
    rq.push(task);
    if rq.len() != 1 {
        return TestResult::Fail;
    }
    if rq.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_push_multiple() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));
    if rq.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_pop_empty() -> TestResult {
    let mut rq = RunQueue::new();
    if rq.pop().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_pop_single() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(42));
    let popped = rq.pop();
    if popped.is_none() {
        return TestResult::Fail;
    }
    if popped.unwrap().id != 42 {
        return TestResult::Fail;
    }
    if !rq.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_fifo_order() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    if rq.pop().unwrap().id != 1 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 2 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 3 {
        return TestResult::Fail;
    }
    if rq.pop().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_clear() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));
    rq.clear();
    if !rq.is_empty() {
        return TestResult::Fail;
    }
    if rq.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_clear_empty() -> TestResult {
    let mut rq = RunQueue::new();
    rq.clear();
    if !rq.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_is_empty_after_pop() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.pop();
    if !rq.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_len_after_operations() -> TestResult {
    let mut rq = RunQueue::new();
    if rq.len() != 0 {
        return TestResult::Fail;
    }
    rq.push(create_task(1));
    if rq.len() != 1 {
        return TestResult::Fail;
    }
    rq.push(create_task(2));
    if rq.len() != 2 {
        return TestResult::Fail;
    }
    rq.pop();
    if rq.len() != 1 {
        return TestResult::Fail;
    }
    rq.pop();
    if rq.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_remove_by_id_existing() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    let removed = rq.remove_by_id(2);
    if removed.is_none() {
        return TestResult::Fail;
    }
    if removed.unwrap().id != 2 {
        return TestResult::Fail;
    }
    if rq.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_remove_by_id_nonexistent() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));

    let removed = rq.remove_by_id(999);
    if removed.is_some() {
        return TestResult::Fail;
    }
    if rq.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_remove_by_id_empty() -> TestResult {
    let mut rq = RunQueue::new();
    let removed = rq.remove_by_id(1);
    if removed.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_remove_by_id_first() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    let removed = rq.remove_by_id(1);
    if removed.is_none() {
        return TestResult::Fail;
    }
    if removed.unwrap().id != 1 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_remove_by_id_last() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));

    let removed = rq.remove_by_id(3);
    if removed.is_none() {
        return TestResult::Fail;
    }
    if removed.unwrap().id != 3 {
        return TestResult::Fail;
    }
    if rq.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_remove_by_id_maintains_order() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.push(create_task(3));
    rq.push(create_task(4));
    rq.push(create_task(5));

    rq.remove_by_id(3);

    if rq.pop().unwrap().id != 1 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 2 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 4 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_mixed_operations() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.pop();
    rq.push(create_task(3));
    rq.remove_by_id(2);
    rq.push(create_task(4));

    if rq.len() != 2 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 3 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_push_after_clear() -> TestResult {
    let mut rq = RunQueue::new();
    rq.push(create_task(1));
    rq.push(create_task(2));
    rq.clear();
    rq.push(create_task(3));

    if rq.len() != 1 {
        return TestResult::Fail;
    }
    if rq.pop().unwrap().id != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_runqueue_large_number_of_tasks() -> TestResult {
    let mut rq = RunQueue::new();
    for i in 0..100 {
        rq.push(create_task(i));
    }
    if rq.len() != 100 {
        return TestResult::Fail;
    }

    for i in 0..100 {
        let task = rq.pop().unwrap();
        if task.id != i {
            return TestResult::Fail;
        }
    }
    if !rq.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
