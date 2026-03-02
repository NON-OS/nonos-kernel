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

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::{Mutex, RwLock};

use super::types::{Pid, MemoryState};

#[derive(Debug)]
pub struct ThreadGroup {
    pub tgid: Pid,
    pub threads: RwLock<Vec<Pid>>,
    pub shared_memory: Option<Arc<Mutex<MemoryState>>>,
    pub active_threads: AtomicU32,
}

impl ThreadGroup {
    pub fn new(leader_pid: Pid) -> Self {
        Self {
            tgid: leader_pid,
            threads: RwLock::new(vec![leader_pid]),
            shared_memory: None,
            active_threads: AtomicU32::new(1),
        }
    }

    pub fn new_with_shared_memory(leader_pid: Pid, memory: Arc<Mutex<MemoryState>>) -> Self {
        Self {
            tgid: leader_pid,
            threads: RwLock::new(vec![leader_pid]),
            shared_memory: Some(memory),
            active_threads: AtomicU32::new(1),
        }
    }

    pub fn add_thread(&self, tid: Pid) {
        self.threads.write().push(tid);
        self.active_threads.fetch_add(1, Ordering::AcqRel);
    }

    pub fn remove_thread(&self, tid: Pid) {
        let mut threads = self.threads.write();
        if let Some(pos) = threads.iter().position(|&t| t == tid) {
            threads.remove(pos);
        }
        self.active_threads.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn thread_count(&self) -> u32 {
        self.active_threads.load(Ordering::Acquire)
    }

    pub fn is_leader(&self, tid: Pid) -> bool {
        tid == self.tgid
    }
}
