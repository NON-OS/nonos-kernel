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

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::RwLock;
use x86_64::VirtAddr;

use super::types::{Pid, ProcessState, Priority, MemoryState};
use super::pcb::ProcessControlBlock;

#[derive(Default)]
pub struct ProcessTable {
    inner: RwLock<Vec<Arc<ProcessControlBlock>>>,
}

impl ProcessTable {
    pub fn add(&self, pcb: Arc<ProcessControlBlock>) {
        self.inner.write().push(pcb);
    }

    pub fn get_all_processes(&self) -> Vec<Arc<ProcessControlBlock>> {
        self.inner.read().clone()
    }

    pub fn find_by_pid(&self, pid: Pid) -> Option<Arc<ProcessControlBlock>> {
        self.inner.read().iter().find(|p| p.pid == pid).cloned()
    }

    pub fn is_active_name(&self, name: &str) -> bool {
        self.inner.read().iter().any(|p| p.name.lock().as_str() == name)
    }

    pub fn is_active_pid(&self, pid: u64) -> bool {
        self.inner.read().iter().any(|p| p.pid as u64 == pid)
    }

    pub fn terminate_process(&self, pid: Pid) -> Result<(), &'static str> {
        let mut inner = self.inner.write();
        if let Some(pos) = inner.iter().position(|p| p.pid == pid) {
            let pcb = &inner[pos];
            *pcb.state.lock() = ProcessState::Terminated(0);
            inner.remove(pos);
            Ok(())
        } else {
            Err("Process not found")
        }
    }

    pub fn get_children_of(&self, parent_pid: Pid) -> Vec<Arc<ProcessControlBlock>> {
        self.inner
            .read()
            .iter()
            .filter(|p| p.parent_pid() == parent_pid)
            .cloned()
            .collect()
    }

    pub fn has_children(&self, pid: Pid) -> bool {
        self.inner.read().iter().any(|p| p.parent_pid() == pid)
    }

    pub fn get_process(&self, pid: Pid) -> Option<Arc<ProcessControlBlock>> {
        self.find_by_pid(pid)
    }

    pub fn set_process_group(&self, pid: Pid, pgid: Pid) -> Result<(), &'static str> {
        if let Some(pcb) = self.find_by_pid(pid) {
            pcb.pgid.store(pgid, Ordering::Relaxed);
            Ok(())
        } else {
            Err("Process not found")
        }
    }

    pub fn set_session_leader(&self, pid: Pid) -> Result<(), &'static str> {
        if let Some(pcb) = self.find_by_pid(pid) {
            pcb.pgid.store(pid, Ordering::Relaxed);
            Ok(())
        } else {
            Err("Process not found")
        }
    }
}

pub static PROCESS_TABLE: ProcessTable = ProcessTable {
    inner: RwLock::new(Vec::new()),
};

pub static CURRENT_PID: AtomicU32 = AtomicU32::new(0);

static NEXT_PID: AtomicU32 = AtomicU32::new(1);

pub fn create_process(name: &str, state: ProcessState, prio: Priority) -> Result<Pid, &'static str> {
    if name.is_empty() {
        return Err("empty name");
    }
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let parent_pid = CURRENT_PID.load(Ordering::Relaxed);
    let pcb = Arc::new(ProcessControlBlock {
        pid,
        tgid: AtomicU32::new(pid),
        ppid: AtomicU32::new(parent_pid),
        pgid: AtomicU32::new(pid),
        sid: AtomicU32::new(pid),
        name: spin::Mutex::new(String::from(name)),
        state: spin::Mutex::new(state),
        priority: spin::Mutex::new(prio),
        memory: spin::Mutex::new(MemoryState {
            code_start: VirtAddr::new(0),
            code_end: VirtAddr::new(0),
            vmas: Vec::new(),
            resident_pages: AtomicU64::new(0),
            next_va: 0x0000_4000_0000,
        }),
        thread_group: None,
        argv: spin::Mutex::new(Vec::new()),
        envp: spin::Mutex::new(Vec::new()),
        caps_bits: AtomicU64::new(u64::MAX),
        exit_code: core::sync::atomic::AtomicI32::new(0),
        zk_proofs_generated: AtomicU64::new(0),
        zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0),
        zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0),
        umask: spin::Mutex::new(0o022),
        root_dir: spin::Mutex::new(String::from("/")),
        clear_child_tid: AtomicU64::new(0),
        set_child_tid: AtomicU64::new(0),
        alarm_time_ms: AtomicU64::new(0),
        tls_base: AtomicU64::new(0),
        stack_base: AtomicU64::new(0),
        clone_flags: AtomicU64::new(0),
        start_time_ms: AtomicU64::new(crate::time::timestamp_millis()),
    });
    PROCESS_TABLE.add(pcb);
    if CURRENT_PID.load(Ordering::Relaxed) == 0 {
        CURRENT_PID.store(pid, Ordering::Relaxed);
    }
    Ok(pid)
}

pub fn allocate_tid() -> Pid {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}
