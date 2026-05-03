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

pub mod accounting;
pub mod acct_record;
pub mod address_space;
pub mod api;
pub mod capabilities;
pub mod clone_flags;
mod clone_pcb;
pub mod context;
pub mod control;
pub mod core;
pub mod exec;
pub mod fd_table;
pub mod fd_types;
pub mod manager;
pub mod nox;
pub mod numa;
pub mod operations;
pub mod operations_exec;
pub mod process_fd_table;
pub mod realtime;
pub mod scheduler;
pub mod signal;
pub mod types;
pub mod userspace;

#[cfg(test)]
pub mod tests;

pub use accounting::{
    clear_records, find_by_pid, get_accounting_stats, get_all_records, get_recent_records,
    AcctRecord, ProcessRecord, ACORE, AFORK, ASU, AXSIG,
};
pub use accounting::{
    disable_accounting, enable_accounting, is_accounting_enabled, record_exit_from_pcb,
    record_process_exit,
};
pub use capabilities::{Capability, CapabilitySet};
pub use clone_flags::{
    CloneArgs, CLONE_CHILD_CLEARTID, CLONE_FILES, CLONE_FS, CLONE_PARENT_SETTID, CLONE_SIGHAND,
    CLONE_THREAD, CLONE_VM,
};
pub use clone_flags::{
    CLONE_CHILD_SETTID, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, CLONE_SETTLS,
};
pub use clone_flags::{CLONE_DETACHED, CLONE_NEWCGROUP, CLONE_PARENT, CLONE_VFORK};
pub use context as nonos_context;
pub use context::CpuContext;
pub use core as nonos_core;
pub use core::{
    allocate_tid, get_process_stats, is_process_active, is_process_active_by_id, isolate_process,
    suspend_process, ProcessManagementStats,
};
pub use core::{
    clear_fpu_state, clear_interrupt_context, has_saved_fpu_state, init_fpu, restore_fpu_state,
    save_fpu_state, save_interrupt_context, INTERRUPT_SAVED_CONTEXTS, INTERRUPT_SAVED_FPU_STATES,
};
pub use core::{
    context_switch, create_process, current_pid, current_process, get_process_table,
    init_process_management,
};
pub use core::{
    Pid, Priority, ProcessControlBlock, ProcessState, ProcessTable, ThreadGroup, CURRENT_PID,
    PROCESS_TABLE,
};
pub use core::{
    ProcessCapabilities as ProcCaps, ProcessCredentials, ProcessMemoryInfo, ProcessTimeInfo,
};
pub use manager::{
    get_process_manager, init_process_manager, is_manager_initialized, ProcessManager,
};
pub use operations::{clone3, clone_process, fork, fork_process};
pub use operations_exec::{
    enumerate_all_processes, get_all_processes, get_current_process,
    get_current_process_capabilities, get_thread_count, get_thread_ids,
};
pub use operations_exec::{
    exec_fn, exec_process, exit_current_process, exit_thread, set_root, set_umask,
    update_memory_usage,
};
pub use signal::SignalState;
pub use types::Process;

pub type ProcessCapabilities = capabilities::CapabilitySet;

pub use api::{
    current_tid, current_uid, get_current_pty, get_parent_pid, get_process, get_tty_pgrp, get_uid,
    last_pid, list_all_pids, release_controlling_tty, resume_process, resume_process_by_pid,
    set_comm, set_controlling_tty, set_cwd, set_tty_pgrp, stop_process,
    terminate_current_with_signal, with_process, with_process_mut,
};
