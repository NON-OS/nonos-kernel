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

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::types::*;

pub struct NoxProcessManager {
    table: RwLock<BTreeMap<NoxPid, Arc<RwLock<NoxProcess>>>>,
    next_pid: AtomicU64,
}

impl NoxProcessManager {
    pub const fn new() -> Self {
        Self {
            table: RwLock::new(BTreeMap::new()),
            next_pid: AtomicU64::new(1),
        }
    }

    #[inline]
    fn alloc_pid(&self) -> NoxPid {
        let raw = self.next_pid.fetch_add(1, Ordering::Relaxed);
        let v = if raw == 0 { 1 } else { raw };
        NoxPid(v)
    }

    pub fn create(
        &self,
        path: &str,
        args: &[&str],
        parent: Option<NoxPid>,
        node: Option<u16>,
    ) -> Result<NoxPid, &'static str> {
        if path.is_empty() || path.len() > PATH_MAX_BYTES {
            return Err("EINVAL");
        }

        // Bound arguments
        let n = min(args.len(), ARGS_MAX_COUNT);
        let mut total = 0usize;
        let mut out_args: Vec<String> = Vec::with_capacity(n);
        for s in args.iter().take(n) {
            total = total.saturating_add(s.len());
            if total > ARGS_MAX_TOTAL_BYTES {
                return Err("E2BIG");
            }
            out_args.push(String::from(*s));
        }

        let pid = self.alloc_pid();
        let proc = NoxProcess {
            pid,
            executable_path: String::from(path),
            args: out_args,
            state: NoxState::Ready,
            created_ns: crate::time::current_time_ns(),
            parent,
            node: node.unwrap_or(0),
            pending_migration_to: None,
        };
        self.table.write().insert(pid, Arc::new(RwLock::new(proc)));
        Ok(pid)
    }

    pub fn get(&self, pid: NoxPid) -> Option<NoxProcess> {
        self.table.read().get(&pid).map(|p| p.read().clone())
    }

    pub fn get_ref(&self, pid: NoxPid) -> Option<Arc<RwLock<NoxProcess>>> {
        self.table.read().get(&pid).cloned()
    }

    pub fn list(&self) -> Vec<NoxPid> {
        self.table.read().keys().copied().collect()
    }

    pub fn list_by_node(&self, node: u16) -> Vec<NoxPid> {
        self.table
            .read()
            .iter()
            .filter_map(|(pid, p)| (p.read().node == node).then_some(*pid))
            .collect()
    }

    pub fn set_state(&self, pid: NoxPid, to: NoxState) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else {
            return Err("ESRCH");
        };
        let cur = p.read().state;
        if !NoxProcess::can_transition(cur, to) {
            return Err("EALREADY");
        }
        *p.write() = NoxProcess {
            state: to,
            ..p.read().clone()
        };
        Ok(())
    }

    pub fn terminate(&self, pid: NoxPid, code: i32) -> Result<(), &'static str> {
        self.set_state(pid, NoxState::Terminated(code))
    }

    pub fn remove(&self, pid: NoxPid) -> Result<bool, &'static str> {
        let mut t = self.table.write();
        match t.get(&pid) {
            None => Ok(false),
            Some(p) => {
                if matches!(p.read().state, NoxState::Terminated(_)) {
                    t.remove(&pid);
                    Ok(true)
                } else {
                    Err("EBUSY")
                }
            }
        }
    }

    pub fn request_migration(&self, pid: NoxPid, to_node: u16) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else {
            return Err("ESRCH");
        };
        let snap = p.read().clone();
        if matches!(snap.state, NoxState::Terminated(_)) {
            return Err("EALREADY");
        }
        if matches!(snap.state, NoxState::Migrating { .. }) {
            return Err("EALREADY");
        }
        let from_node = snap.node;
        let mut w = p.write();
        w.pending_migration_to = Some(to_node);
        w.state = NoxState::Migrating { from_node, to_node };
        Ok(())
    }

    pub fn complete_migration(&self, pid: NoxPid) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else {
            return Err("ESRCH");
        };
        let mut w = p.write();
        match w.state {
            NoxState::Migrating { to_node, .. } => {
                w.node = to_node;
                w.pending_migration_to = None;
                w.state = NoxState::Ready;
                Ok(())
            }
            NoxState::Terminated(_) => Err("EALREADY"),
            _ => Err("EALREADY"),
        }
    }

    pub fn cancel_migration(&self, pid: NoxPid) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else {
            return Err("ESRCH");
        };
        let mut w = p.write();
        match w.state {
            NoxState::Migrating { .. } => {
                w.pending_migration_to = None;
                w.state = NoxState::Ready;
                Ok(())
            }
            NoxState::Terminated(_) => Err("EALREADY"),
            _ => Err("EALREADY"),
        }
    }

    pub fn set_args(&self, pid: NoxPid, args: &[&str]) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else {
            return Err("ESRCH");
        };
        let n = min(args.len(), ARGS_MAX_COUNT);
        let mut total = 0usize;
        let mut out: Vec<String> = Vec::with_capacity(n);
        for s in args.iter().take(n) {
            total = total.saturating_add(s.len());
            if total > ARGS_MAX_TOTAL_BYTES {
                return Err("E2BIG");
            }
            out.push(String::from(*s));
        }
        p.write().args = out;
        Ok(())
    }

    pub fn set_executable_path(&self, pid: NoxPid, path: &str) -> Result<(), &'static str> {
        if path.is_empty() || path.len() > PATH_MAX_BYTES {
            return Err("EINVAL");
        }
        let Some(p) = self.table.read().get(&pid).cloned() else {
            return Err("ESRCH");
        };
        p.write().executable_path = String::from(path);
        Ok(())
    }
}
