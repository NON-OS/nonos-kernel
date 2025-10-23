#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

/// Bounded limits to prevent unbounded metadata growth
const PATH_MAX_BYTES: usize = 4096;
const ARGS_MAX_COUNT: usize = 128;
const ARGS_MAX_TOTAL_BYTES: usize = 32 * 1024; // 32 KiB

/// Identifier for a managed process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoxPid(pub u64);

/// Lifecycle states for processes managed by this module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoxState {
    Ready,
    Running,
    Suspended,
    Migrating { from_node: u16, to_node: u16 },
    Terminated(i32),
}

/// Process descriptor
#[derive(Debug, Clone)]
pub struct NoxProcess {
    pub pid: NoxPid,
    pub executable_path: String,
    pub args: Vec<String>,
    pub state: NoxState,
    pub created_ns: u64,
    pub parent: Option<NoxPid>,
    pub node: u16,                      // current placement node
    pub pending_migration_to: Option<u16>,
}

impl NoxProcess {
    #[inline]
    fn can_transition(from: NoxState, to: NoxState) -> bool {
        use NoxState::*;
        match (from, to) {
            (Terminated(_), _) => false,                 // terminal state
            (_, Terminated(_)) => true,                  // anything can terminate
            (Ready, Running) | (Running, Suspended) | (Suspended, Ready) => true,
            (Ready, Suspended) | (Suspended, Running) => true,
            (Running, Ready) => true,
            (Migrating { .. }, Ready) => true,
            (Ready, Migrating { .. }) | (Running, Migrating { .. }) | (Suspended, Migrating { .. }) => true,
            // No direct transitions between distinct Migrating states
            (Migrating { .. }, Migrating { .. }) => false,
            // Same state transitions (no-op but allowed)
            (Ready, Ready) | (Running, Running) | (Suspended, Suspended) => true,
            // Migration to runtime states
            (Migrating { .. }, Running) | (Migrating { .. }, Suspended) => true,
        }
    }
}

/// Manager storing processes and handling advanced lifecycle and migration
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

    /// Create a new process record with bounded path/args, initial node placement, and optional parent.
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

    /// Snapshot a process (clone) if it exists.
    pub fn get(&self, pid: NoxPid) -> Option<NoxProcess> {
        self.table.read().get(&pid).map(|p| p.read().clone())
    }

    /// Get a shared reference to the process lock for advanced callers.
    pub fn get_ref(&self, pid: NoxPid) -> Option<Arc<RwLock<NoxProcess>>> {
        self.table.read().get(&pid).cloned()
    }

    /// List all process ids.
    pub fn list(&self) -> Vec<NoxPid> {
        self.table.read().keys().copied().collect()
    }

    /// List PIDs filtered by node.
    pub fn list_by_node(&self, node: u16) -> Vec<NoxPid> {
        self.table
            .read()
            .iter()
            .filter_map(|(pid, p)| (p.read().node == node).then_some(*pid))
            .collect()
    }

    /// Change state with validation. Returns EALREADY for terminal state or invalid transition.
    pub fn set_state(&self, pid: NoxPid, to: NoxState) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else { return Err("ESRCH"); };
        let cur = p.read().state;
        if !NoxProcess::can_transition(cur, to) {
            return Err("EALREADY");
        }
        *p.write() = NoxProcess { state: to, ..p.read().clone() };
        Ok(())
    }

    /// Terminate a process with an exit code.
    pub fn terminate(&self, pid: NoxPid, code: i32) -> Result<(), &'static str> {
        self.set_state(pid, NoxState::Terminated(code))
    }

    /// Remove a process record (only allowed if Terminated).
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

    /// Request a migration to another node. Puts process into Migrating state.
    ///
    /// Errors:
    /// - ESRCH: process not found
    /// - EALREADY: already terminated or already migrating
    pub fn request_migration(&self, pid: NoxPid, to_node: u16) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else { return Err("ESRCH"); };
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

    /// Complete a previously requested migration. Moves process to target node and Ready state.
    pub fn complete_migration(&self, pid: NoxPid) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else { return Err("ESRCH"); };
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

    /// Cancel an in-flight migration and return to Ready state without node change.
    pub fn cancel_migration(&self, pid: NoxPid) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else { return Err("ESRCH"); };
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

    /// Update process arguments with bounds checking.
    pub fn set_args(&self, pid: NoxPid, args: &[&str]) -> Result<(), &'static str> {
        let Some(p) = self.table.read().get(&pid).cloned() else { return Err("ESRCH"); };
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

    /// Replace executable path (bounded).
    pub fn set_executable_path(&self, pid: NoxPid, path: &str) -> Result<(), &'static str> {
        if path.is_empty() || path.len() > PATH_MAX_BYTES {
            return Err("EINVAL");
        }
        let Some(p) = self.table.read().get(&pid).cloned() else { return Err("ESRCH"); };
        p.write().executable_path = String::from(path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn create_and_get() {
        let mgr = NoxProcessManager::new();
        let pid = mgr.create("/bin/app", &["-v", "--opt"], None, Some(1)).unwrap();
        let snap = mgr.get(pid).unwrap();
        assert_eq!(snap.pid, pid);
        assert_eq!(snap.node, 1);
        assert_eq!(snap.state, NoxState::Ready);
        assert_eq!(snap.executable_path, "/bin/app");
        assert_eq!(snap.args, vec![String::from("-v"), String::from("--opt")]);
    }

    #[test]
    fn invalid_inputs() {
        let mgr = NoxProcessManager::new();
        assert_eq!(mgr.create("", &[], None, None).unwrap_err(), "EINVAL");

        // Args too large
        let huge = "A".repeat(ARGS_MAX_TOTAL_BYTES + 1);
        assert_eq!(
            mgr.create("/bin/x", &[&huge], None, None).unwrap_err(),
            "E2BIG"
        );

        // Path too long
        let long_path = "p".repeat(PATH_MAX_BYTES + 1);
        assert_eq!(
            mgr.create(&long_path, &[], None, None).unwrap_err(),
            "EINVAL"
        );
    }

    #[test]
    fn state_transitions() {
        let mgr = NoxProcessManager::new();
        let pid = mgr.create("/bin/a", &[], None, None).unwrap();

        // Ready -> Running -> Suspended -> Ready
        mgr.set_state(pid, NoxState::Running).unwrap();
        assert_eq!(mgr.get(pid).unwrap().state, NoxState::Running);
        mgr.set_state(pid, NoxState::Suspended).unwrap();
        assert_eq!(mgr.get(pid).unwrap().state, NoxState::Suspended);
        mgr.set_state(pid, NoxState::Ready).unwrap();
        assert_eq!(mgr.get(pid).unwrap().state, NoxState::Ready);

        // Terminate and reject further transitions
        mgr.terminate(pid, 0).unwrap();
        assert!(mgr.set_state(pid, NoxState::Ready).is_err());
    }

    #[test]
    fn migration_flow() {
        let mgr = NoxProcessManager::new();
        let pid = mgr.create("/bin/m", &[], None, Some(0)).unwrap();
        mgr.request_migration(pid, 2).unwrap();
        {
            let p = mgr.get(pid).unwrap();
            assert!(matches!(p.state, NoxState::Migrating { from_node: 0, to_node: 2 }));
            assert_eq!(p.pending_migration_to, Some(2));
        }
        mgr.complete_migration(pid).unwrap();
        let p2 = mgr.get(pid).unwrap();
        assert_eq!(p2.node, 2);
        assert_eq!(p2.state, NoxState::Ready);
        assert_eq!(p2.pending_migration_to, None);
    }

    #[test]
    fn cancel_migration() {
        let mgr = NoxProcessManager::new();
        let pid = mgr.create("/bin/m2", &[], None, Some(1)).unwrap();
        mgr.request_migration(pid, 3).unwrap();
        mgr.cancel_migration(pid).unwrap();
        let p = mgr.get(pid).unwrap();
        assert_eq!(p.node, 1);
        assert_eq!(p.state, NoxState::Ready);
        assert_eq!(p.pending_migration_to, None);
    }

    #[test]
    fn remove_only_after_terminated() {
        let mgr = NoxProcessManager::new();
        let pid = mgr.create("/bin/rm", &[], None, None).unwrap();
        assert_eq!(mgr.remove(pid).unwrap_err(), "EBUSY");
        mgr.terminate(pid, 9).unwrap();
        assert!(mgr.remove(pid).unwrap());
        assert!(mgr.get(pid).is_none());
    }

    #[test]
    fn list_and_filter_by_node() {
        let mgr = NoxProcessManager::new();
        let a = mgr.create("/bin/a", &[], None, Some(0)).unwrap();
        let b = mgr.create("/bin/b", &[], None, Some(1)).unwrap();
        let c = mgr.create("/bin/c", &[], None, Some(1)).unwrap();
        let all = mgr.list();
        assert!(all.contains(&a) && all.contains(&b) && all.contains(&c));
        let n1 = mgr.list_by_node(1);
        assert!(n1.contains(&b) && n1.contains(&c) && !n1.contains(&a));
    }
}
