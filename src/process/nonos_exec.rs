#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Once, RwLock};

pub type NonosExecPid = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosExecState {
    Ready,
    Running,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct NonosExecContext {
    pub pid: NonosExecPid,
    pub state: NonosExecState,
    pub entry_point: u64,
    pub created_ms: u64,
}

#[derive(Debug)]
pub struct NonosExecCreate {
    pub executable_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NonosExecStats {
    pub active_processes: usize,
    pub total_created: u64,
    pub total_terminated: u64,
}

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

    /// Create an execution context from an executable image.
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

    /// Transition a context to Running.
    pub fn execute(&self, pid: NonosExecPid) -> Result<(), &'static str> {
        let mut t = self.table.write();
        let p = t.get_mut(&pid).ok_or("ESRCH")?;
        if p.state == NonosExecState::Terminated {
            return Err("EALREADY");
        }
        p.state = NonosExecState::Running;
        Ok(())
    }

    /// Suspend a running context.
    pub fn suspend(&self, pid: NonosExecPid) -> Result<(), &'static str> {
        let mut t = self.table.write();
        let p = t.get_mut(&pid).ok_or("ESRCH")?;
        if p.state == NonosExecState::Terminated {
            return Err("EALREADY");
        }
        p.state = NonosExecState::Suspended;
        Ok(())
    }

    /// Terminate a context.
    pub fn terminate(&self, pid: NonosExecPid) -> Result<(), &'static str> {
        let mut t = self.table.write();
        let p = t.get_mut(&pid).ok_or("ESRCH")?;
        if p.state != NonosExecState::Terminated {
            p.state = NonosExecState::Terminated;
            self.total_terminated.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Get a snapshot of executor stats.
    pub fn stats(&self) -> NonosExecStats {
        let t = self.table.read();
        NonosExecStats {
            active_processes: t.values().filter(|p| p.state != NonosExecState::Terminated).count(),
            total_created: self.total_created.load(Ordering::Relaxed),
            total_terminated: self.total_terminated.load(Ordering::Relaxed),
        }
    }

    /// Read-only view of a context.
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // For testing, we simulate a non-zero entry by providing bytes that parser accepts.
    fn fake_exe_with_entry(entry: u64) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[..8].copy_from_slice(&entry.to_le_bytes());
        v
    }

    #[test]
    fn create_execute_terminate_flow() {
        let exe = fake_exe_with_entry(0x401000);
        let pid = create_nonos_process(NonosExecCreate { executable_data: exe }).expect("create");
        let ex = get_nonos_executor().get(pid).expect("ctx");
        assert_eq!(ex.state, NonosExecState::Ready);
        assert_eq!(ex.entry_point, 0x401000);

        execute_nonos_process(pid).expect("run");
        let ex = get_nonos_executor().get(pid).unwrap();
        assert_eq!(ex.state, NonosExecState::Running);

        suspend_nonos_process(pid).expect("suspend");
        let ex = get_nonos_executor().get(pid).unwrap();
        assert_eq!(ex.state, NonosExecState::Suspended);

        terminate_nonos_process(pid).expect("term");
        let ex = get_nonos_executor().get(pid).unwrap();
        assert_eq!(ex.state, NonosExecState::Terminated);

        let st = nonos_executor_stats();
        assert!(st.total_created >= 1);
        assert!(st.total_terminated >= 1);
        assert!(st.active_processes <= st.total_created as usize);
    }

    #[test]
    fn invalid_executable_rejected() {
        // Empty buffer
        assert!(create_nonos_process(NonosExecCreate { executable_data: Vec::new() }).is_err());
        // Parser returns entry=0 -> ENOEXEC
        let bad = fake_exe_with_entry(0);
        assert_eq!(
            create_nonos_process(NonosExecCreate { executable_data: bad }).unwrap_err(),
            "ENOEXEC"
        );
    }

    #[test]
    fn unknown_pid_errors() {
        assert_eq!(execute_nonos_process(0xDEAD).unwrap_err(), "ESRCH");
        assert_eq!(suspend_nonos_process(0xDEAD).unwrap_err(), "ESRCH");
        assert_eq!(terminate_nonos_process(0xDEAD).unwrap_err(), "ESRCH");
    }
}
