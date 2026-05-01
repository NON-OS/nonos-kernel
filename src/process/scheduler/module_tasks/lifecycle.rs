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

use super::super::types::ModuleTaskResult;
use super::state::MODULE_TASKS;
use super::super::core::get_queue;
use alloc::vec::Vec;

pub fn terminate_module_tasks(module_id: u64) -> ModuleTaskResult<()> {
    let task_ids: Vec<u64> = {
        let module_tasks = MODULE_TASKS.read();
        module_tasks.get(&module_id).map(|t| t.iter().copied().collect()).unwrap_or_default()
    };
    for task_id in task_ids {
        terminate_task(task_id);
    }
    Ok(())
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
