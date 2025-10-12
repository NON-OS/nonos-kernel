#![no_std]

extern crate alloc;

pub mod nonos_core;
pub mod nonos_control;
pub mod nonos_scheduler;
pub mod nonos_numa;
pub mod nonos_realtime;
pub mod nonos_capabilities;
pub mod nonos_exec;
pub mod nox_process_mng;
pub mod nonos_context;

// Re-exports with concise names
pub use nonos_core as core;
pub use nonos_control as control;
pub use nonos_scheduler as scheduler;
pub use nonos_numa as numa;
pub use nonos_realtime as realtime;
pub use nonos_capabilities as capabilities;
pub use nonos_exec as exec;
pub use nox_process_mng as nox;
pub use nonos_context as ctx;

use alloc::{string::String, sync::Arc, vec::Vec};
use spin::{Once, RwLock};
use x86_64::structures::paging::PageTableFlags;

// Capability view exposed to syscall gate and policy
pub type ProcessCapabilities = capabilities::CapabilitySet;

// Keep external callers stable
#[inline]
pub fn init_process_management() {
    core::init_process_management()
}
#[inline]
pub fn current_process() -> Option<Arc<core::ProcessControlBlock>> {
    core::current_process()
}
#[inline]
pub fn current_pid() -> Option<u32> {
    core::current_pid()
}
#[inline]
pub fn create_process(
    name: &str,
    state: core::ProcessState,
    prio: core::Priority,
) -> Result<u32, &'static str> {
    core::create_process(name, state, prio)
}
#[inline]
pub fn context_switch(to: u32) -> Result<(), &'static str> {
    core::context_switch(to)
}
#[inline]
pub fn get_process_table() -> &'static core::ProcessTable {
    core::get_process_table()
}
#[inline]
pub fn get_process_stats() -> core::ProcessManagementStats {
    core::get_process_stats()
}
#[inline]
pub fn isolate_process(pid: u32) -> Result<(), &'static str> {
    core::isolate_process(pid)
}
#[inline]
pub fn suspend_process(pid: u32) -> Result<(), &'static str> {
    core::suspend_process(pid)
}

// Lightweight process snapshot for non-core consumers
#[derive(Clone)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pcb: Option<Arc<core::ProcessControlBlock>>,
}

impl Process {
    #[inline]
    pub fn pid(&self) -> u32 {
        self.pid
    }
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn serialize_state(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.pid.to_le_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out
    }

    pub fn terminate_with_signal(&self, signal: i32) {
        if let Some(ref pcb) = self.pcb {
            pcb.terminate(signal);
        }
    }

    pub fn command_line(&self) -> Option<String> {
        self.pcb.as_ref().and_then(|pcb| {
            let argv = pcb.argv.lock();
            if argv.is_empty() {
                None
            } else {
                Some(argv.join(" "))
            }
        })
    }

    pub fn environment_variables(&self) -> Option<Vec<(String, String)>> {
        self.pcb.as_ref().and_then(|pcb| {
            let envp = pcb.envp.lock();
            if envp.is_empty() {
                return None;
            }
            let mut v = Vec::with_capacity(envp.len());
            for e in envp.iter() {
                if let Some(eq) = e.find('=') {
                    v.push((String::from(&e[..eq]), String::from(&e[eq + 1..])));
                } else {
                    v.push((e.clone(), String::new()));
                }
            }
            Some(v)
        })
    }

    pub fn is_authorized_executable_region(&self, address: u64) -> bool {
        self.pcb.as_ref().map_or(false, |pcb| {
            let mem = pcb.memory.lock();
            if address >= mem.code_start.as_u64() && address < mem.code_end.as_u64() {
                return true;
            }
            for vma in &mem.vmas {
                if address >= vma.start.as_u64()
                    && address < vma.end.as_u64()
                    && vma.flags.contains(PageTableFlags::PRESENT)
                {
                    return true;
                }
            }
            false
        })
    }
}

// Per-process metadata registry
pub struct ProcessManager {
    processes: RwLock<alloc::collections::BTreeMap<u32, Process>>,
}
impl ProcessManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            processes: RwLock::new(alloc::collections::BTreeMap::new()),
        }
    }
    pub fn get_process(&self, pid: u32) -> Option<Process> {
        self.processes.read().get(&pid).cloned()
    }
    pub fn get_active_process_count(&self) -> usize {
        self.processes.read().len()
    }
    pub fn pause_process(&self, pid: u32) -> Result<(), &'static str> {
        suspend_process(pid).map_err(|_| "suspend failed")
    }
    pub fn upsert(&self, p: Process) {
        self.processes.write().insert(p.pid, p);
    }
}

static PROCESS_MANAGER: Once<ProcessManager> = Once::new();
#[inline]
pub fn init_process_manager() {
    PROCESS_MANAGER.call_once(ProcessManager::new);
}
#[inline]
pub fn get_process_manager() -> &'static ProcessManager {
    PROCESS_MANAGER
        .get()
        .expect("process manager not initialized")
}

#[inline]
pub fn enumerate_all_processes() -> Vec<Process> {
    core::get_process_table()
        .get_all_processes()
        .into_iter()
        .map(|pcb| {
            let name = pcb.name.lock().clone();
            Process {
                pid: pcb.pid,
                name,
                pcb: Some(pcb),
            }
        })
        .collect()
}

#[inline]
pub fn get_all_processes() -> Vec<Process> {
    enumerate_all_processes()
}

#[inline]
pub fn get_current_process_capabilities() -> ProcessCapabilities {
    if let Some(pcb) = current_process() {
        let bits = pcb
            .caps_bits
            .load(core::sync::atomic::Ordering::Relaxed);
        capabilities::CapabilitySet::from_bits(bits)
    } else {
        capabilities::CapabilitySet::from_bits(u64::MAX)
    }
}

#[inline]
pub fn exit_current_process(status: i32) -> ! {
    // Route to the kernel's syscall exit path (no halt loop).
    core::syscalls::sys_exit(status)
}
