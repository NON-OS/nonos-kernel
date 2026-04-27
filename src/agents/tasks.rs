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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub const MAX_TASKS: usize = 64;

#[derive(Clone, Copy, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Complete,
    Failed,
    Cancelled,
}

#[derive(Clone)]
pub struct AgentTask {
    pub id: u32,
    pub agent_id: u32,
    pub description: Vec<u8>,
    pub status: TaskStatus,
    pub result: Vec<u8>,
    pub created_at: u64,
    pub completed_at: u64,
}

static TASKS: Mutex<Vec<AgentTask>> = Mutex::new(Vec::new());
static NEXT_TASK_ID: AtomicU32 = AtomicU32::new(1);

pub fn create_task(agent_id: u32, description: &[u8]) -> u32 {
    let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
    let task = AgentTask {
        id,
        agent_id,
        description: description.to_vec(),
        status: TaskStatus::Pending,
        result: Vec::new(),
        created_at: crate::time::timestamp_millis(),
        completed_at: 0,
    };
    let mut tasks = TASKS.lock();
    if tasks.len() >= MAX_TASKS {
        tasks.remove(0);
    }
    tasks.push(task);
    id
}

pub fn update_task_status(id: u32, status: TaskStatus, result: Option<&[u8]>) {
    let mut tasks = TASKS.lock();
    if let Some(t) = tasks.iter_mut().find(|t| t.id == id) {
        t.status = status;
        if let Some(r) = result {
            t.result = r.to_vec();
        }
        if status == TaskStatus::Complete || status == TaskStatus::Failed {
            t.completed_at = crate::time::timestamp_millis();
        }
    }
}

pub fn get_task(id: u32) -> Option<AgentTask> {
    TASKS.lock().iter().find(|t| t.id == id).cloned()
}
pub fn list_agent_tasks(agent_id: u32) -> Vec<AgentTask> {
    TASKS.lock().iter().filter(|t| t.agent_id == agent_id).cloned().collect()
}
pub fn pending_tasks(agent_id: u32) -> Vec<AgentTask> {
    TASKS
        .lock()
        .iter()
        .filter(|t| t.agent_id == agent_id && t.status == TaskStatus::Pending)
        .cloned()
        .collect()
}

pub fn cancel_task(id: u32) -> bool {
    let mut tasks = TASKS.lock();
    if let Some(t) = tasks.iter_mut().find(|t| t.id == id && t.status == TaskStatus::Pending) {
        t.status = TaskStatus::Cancelled;
        true
    } else {
        false
    }
}
