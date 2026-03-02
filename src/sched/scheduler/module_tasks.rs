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

use alloc::collections::{BTreeSet, BTreeMap};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::sched::task::Task;
use super::types::ModuleTaskResult;
use super::core::{spawn, get_queue};

static MODULE_TASKS: spin::RwLock<BTreeMap<u64, BTreeSet<u64>>> = spin::RwLock::new(BTreeMap::new());
static NEXT_MODULE_TASK_ID: AtomicU64 = AtomicU64::new(1);

pub fn spawn_module_task(
    module_id: u64,
    entry_point: u64,
    stack_pointer: u64,
    priority: u8,
) -> ModuleTaskResult<u64> {
    let task_id = NEXT_MODULE_TASK_ID.fetch_add(1, Ordering::SeqCst);

    let task = Task::new_module_task(task_id, module_id, entry_point, stack_pointer, priority);

    {
        let mut module_tasks = MODULE_TASKS.write();
        module_tasks
            .entry(module_id)
            .or_insert_with(BTreeSet::new)
            .insert(task_id);
    }

    spawn(task);

    Ok(task_id)
}

pub fn terminate_module_tasks(module_id: u64) -> ModuleTaskResult<()> {
    let task_ids: Vec<u64> = {
        let module_tasks = MODULE_TASKS.read();
        module_tasks
            .get(&module_id)
            .map(|tasks| tasks.iter().copied().collect())
            .unwrap_or_default()
    };

    for task_id in task_ids {
        terminate_task(task_id);
    }

    Ok(())
}

pub fn has_running_tasks(module_id: u64) -> bool {
    let module_tasks = MODULE_TASKS.read();
    module_tasks
        .get(&module_id)
        .map(|tasks| !tasks.is_empty())
        .unwrap_or(false)
}

pub fn force_kill_module_tasks(module_id: u64) {
    let mut module_tasks = MODULE_TASKS.write();
    if let Some(tasks) = module_tasks.remove(&module_id) {
        for task_id in tasks {
            force_kill_task(task_id);
        }
    }
}

fn terminate_task(task_id: u64) {
    let mut rq = get_queue().lock();
    rq.remove_by_id(task_id);
    remove_from_module_tasks(task_id);
}

fn force_kill_task(task_id: u64) {
    let mut rq = get_queue().lock();
    rq.remove_by_id(task_id);
}

fn remove_from_module_tasks(task_id: u64) {
    let mut module_tasks = MODULE_TASKS.write();
    for tasks in module_tasks.values_mut() {
        tasks.remove(&task_id);
    }
}
