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

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Once, RwLock};

use super::types::*;

pub struct NonosExecutor {
    table: RwLock<BTreeMap<NonosExecPid, NonosExecContext>>,
    next_pid: AtomicU64,
    total_created: AtomicU64,
    total_terminated: AtomicU64,
}

impl NonosExecutor {
    pub const fn new() -> Self {
        Self {
            table: RwLock::new(BTreeMap::new()),
            next_pid: AtomicU64::new(1),
            total_created: AtomicU64::new(0),
            total_terminated: AtomicU64::new(0),
        }
    }

    #[inline]
    fn alloc_pid(&self) -> NonosExecPid {
        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
        if pid == 0 { 1 } else { pid }
    }

    pub fn create(&self, req: NonosExecCreate) -> Result<NonosExecPid, &'static str> {
        if req.executable_data.is_empty() {
            return Err("EINVAL"); // empty executable
        }
        let entry = crate::elf::minimal::entry_from_bytes(&req.executable_data).unwrap_or(0);
        if entry == 0 {
            return Err("ENOEXEC"); // invalid executable format
        }

        let pid = self.alloc_pid();
        let ctx = NonosExecContext {
            pid,
            state: NonosExecState::Ready,
            entry_point: entry,
            created_ms: crate::time::timestamp_millis(),
        };

        self.table.write().insert(pid, ctx);
        self.total_created.fetch_add(1, Ordering::Relaxed);
        Ok(pid)
    }

    pub fn execute(&self, pid: NonosExecPid) -> Result<(), &'static str> {
        let mut t = self.table.write();
        let p = t.get_mut(&pid).ok_or("ESRCH")?;
        if p.state == NonosExecState::Terminated {
            return Err("EALREADY");
        }
        p.state = NonosExecState::Running;
        Ok(())
    }

    pub fn suspend(&self, pid: NonosExecPid) -> Result<(), &'static str> {
        let mut t = self.table.write();
        let p = t.get_mut(&pid).ok_or("ESRCH")?;
        if p.state == NonosExecState::Terminated {
            return Err("EALREADY");
        }
        p.state = NonosExecState::Suspended;
        Ok(())
    }

    pub fn terminate(&self, pid: NonosExecPid) -> Result<(), &'static str> {
        let mut t = self.table.write();
        let p = t.get_mut(&pid).ok_or("ESRCH")?;
        if p.state != NonosExecState::Terminated {
            p.state = NonosExecState::Terminated;
            self.total_terminated.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn stats(&self) -> NonosExecStats {
        let t = self.table.read();
        NonosExecStats {
            active_processes: t.values().filter(|p| p.state != NonosExecState::Terminated).count(),
            total_created: self.total_created.load(Ordering::Relaxed),
            total_terminated: self.total_terminated.load(Ordering::Relaxed),
        }
    }

    pub fn get(&self, pid: NonosExecPid) -> Option<NonosExecContext> {
        self.table.read().get(&pid).cloned()
    }
}

// Global, safe, lazily-initialized executor
static EXECUTOR: Once<NonosExecutor> = Once::new();

#[inline]
pub fn get_nonos_executor() -> &'static NonosExecutor {
    EXECUTOR.call_once(NonosExecutor::new)
}

// Entry points that do not rely on external init order.
#[inline]
pub fn create_nonos_process(req: NonosExecCreate) -> Result<NonosExecPid, &'static str> {
    get_nonos_executor().create(req)
}

#[inline]
pub fn execute_nonos_process(pid: NonosExecPid) -> Result<(), &'static str> {
    get_nonos_executor().execute(pid)
}

#[inline]
pub fn suspend_nonos_process(pid: NonosExecPid) -> Result<(), &'static str> {
    get_nonos_executor().suspend(pid)
}

#[inline]
pub fn terminate_nonos_process(pid: NonosExecPid) -> Result<(), &'static str> {
    get_nonos_executor().terminate(pid)
}

#[inline]
pub fn nonos_executor_stats() -> NonosExecStats {
    get_nonos_executor().stats()
}
