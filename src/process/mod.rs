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

pub mod core;
pub mod types;
pub mod manager;
pub mod fd_types;
pub mod fd_table;
pub mod clone_flags;
mod clone_pcb;
pub mod operations;
pub mod operations_exec;
pub mod control;
pub mod scheduler;
pub mod numa;
pub mod realtime;
pub mod capabilities;
pub mod exec;
pub mod nox;
pub mod context;
pub mod userspace;
pub mod elf_loader;
pub mod address_space;
pub mod accounting;
pub mod signal;

pub use core::{
    ProcessControlBlock, ProcessTable, ProcessState, Priority, Pid, ThreadGroup,
    PROCESS_TABLE, CURRENT_PID,
    init_process_management, current_process, current_pid,
    create_process, context_switch, get_process_table, get_process_stats,
    isolate_process, suspend_process, is_process_active, is_process_active_by_id,
    ProcessManagementStats, allocate_tid,
};

pub use types::Process;

pub use manager::{
    ProcessManager, init_process_manager, get_process_manager, is_manager_initialized,
};

pub use clone_flags::{
    CloneArgs,
    CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND, CLONE_THREAD,
    CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_SETTLS,
    CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWNS,
    CLONE_NEWUTS, CLONE_NEWCGROUP, CLONE_PARENT, CLONE_VFORK, CLONE_DETACHED,
};

pub use operations::{fork_process, fork, clone_process, clone3};

pub use operations_exec::{
    exec_process, exec_fn, set_umask, set_root, update_memory_usage,
    exit_current_process, exit_thread, get_thread_count, get_thread_ids,
    get_current_process, get_current_process_capabilities,
    enumerate_all_processes, get_all_processes,
};

pub use capabilities::{CapabilitySet, Capability};

pub use context::CpuContext;

pub use accounting::{
    enable_accounting, disable_accounting, is_accounting_enabled,
    record_process_exit, record_exit_from_pcb, get_accounting_stats,
    get_recent_records, get_all_records, clear_records, find_by_pid,
    ProcessRecord, AcctRecord, AFORK, ASU, ACORE, AXSIG,
};

pub type ProcessCapabilities = capabilities::CapabilitySet;
