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

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::{Once, RwLock};

use super::core::suspend_process;
use super::types::Process;

pub struct ProcessManager {
    processes: RwLock<BTreeMap<u32, Process>>,
}

impl ProcessManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            processes: RwLock::new(BTreeMap::new()),
        }
    }

    pub const fn new_const() -> Self {
        Self {
            processes: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn get_process(&self, pid: u32) -> Option<Process> {
        self.processes.read().get(&pid).cloned()
    }

    pub fn get_active_process_count(&self) -> usize {
        self.processes.read().len()
    }

    pub fn pause_process(&self, pid: u32) -> Result<(), &'static str> {
        suspend_process(pid)
    }

    pub fn upsert(&self, p: Process) {
        self.processes.write().insert(p.pid, p);
    }

    pub fn remove(&self, pid: u32) -> Option<Process> {
        self.processes.write().remove(&pid)
    }

    pub fn get_all_pids(&self) -> alloc::vec::Vec<u32> {
        self.processes.read().keys().copied().collect()
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

static PROCESS_MANAGER: Once<ProcessManager> = Once::new();

#[inline]
pub fn init_process_manager() {
    PROCESS_MANAGER.call_once(ProcessManager::new);
}

#[inline]
pub fn get_process_manager() -> &'static ProcessManager {
    if !is_manager_initialized() {
        init_process_manager();
    }
    PROCESS_MANAGER
        .get()
        .unwrap_or_else(|| {
            static FALLBACK: ProcessManager = ProcessManager::new_const();
            &FALLBACK
        })
}

#[inline]
pub fn try_get_process_manager() -> Option<&'static ProcessManager> {
    PROCESS_MANAGER.get()
}

#[inline]
pub fn is_manager_initialized() -> bool {
    PROCESS_MANAGER.get().is_some()
}
