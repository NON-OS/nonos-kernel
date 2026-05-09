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

use super::clone_flags::CLONE_PARENT;
use super::core::types::{ProcessIoStats, ProcessTimeInfo};
use super::core::{MemoryState, Priority, ProcessControlBlock, ProcessState, ThreadGroup};
use super::signal::SignalState;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

fn copy_memory(parent: &Arc<ProcessControlBlock>) -> MemoryState {
    let pm = parent.memory.lock();
    MemoryState {
        code_start: pm.code_start,
        code_end: pm.code_end,
        vmas: pm.vmas.clone(),
        resident_pages: AtomicU64::new(pm.resident_pages.load(Ordering::Relaxed)),
        next_va: pm.next_va,
    }
}

pub(crate) fn create_thread_pcb(
    parent: &Arc<ProcessControlBlock>,
    tid: u32,
    name: &str,
    priority: Priority,
    caps: u64,
    tgid: u32,
    pgid: u32,
    sid: u32,
    flags: u64,
    stack: u64,
    tls: u64,
    child_tid_ptr: u64,
) -> Result<Arc<ProcessControlBlock>, i32> {
    let memory = copy_memory(parent);
    let thread_group =
        parent.thread_group.clone().unwrap_or_else(|| Arc::new(ThreadGroup::new(tgid)));
    let (argv, envp) = (parent.argv.lock().clone(), parent.envp.lock().clone());
    let (umask, root_dir, cwd) =
        (*parent.umask.lock(), parent.root_dir.lock().clone(), parent.cwd.lock().clone());
    let pcb = Arc::new(ProcessControlBlock {
        pid: tid,
        tgid: AtomicU32::new(tgid),
        ppid: AtomicU32::new(parent.pid),
        pgid: AtomicU32::new(pgid),
        sid: AtomicU32::new(sid),
        name: spin::Mutex::new(String::from(name)),
        state: spin::Mutex::new(ProcessState::Ready),
        priority: spin::Mutex::new(priority),
        memory: spin::Mutex::new(memory),
        thread_group: Some(thread_group),
        argv: spin::Mutex::new(argv),
        envp: spin::Mutex::new(envp),
        caps_bits: AtomicU64::new(caps),
        exit_code: AtomicI32::new(0),
        zk_proofs_generated: AtomicU64::new(0),
        zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0),
        zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0),
        umask: spin::Mutex::new(umask),
        root_dir: spin::Mutex::new(root_dir),
        cwd: spin::Mutex::new(cwd),
        clear_child_tid: AtomicU64::new(0),
        set_child_tid: AtomicU64::new(child_tid_ptr),
        alarm_time_ms: AtomicU64::new(0),
        tls_base: AtomicU64::new(tls),
        stack_base: AtomicU64::new(stack),
        clone_flags: AtomicU64::new(flags),
        start_time_ms: AtomicU64::new(crate::time::timestamp_millis()),
        fd_table: parent.fd_table.fork(),
        signals: spin::Mutex::new(parent.signals.lock().clone_for_fork()),
        time_info: spin::Mutex::new(ProcessTimeInfo::default()),
        memory_info: spin::Mutex::new(*parent.memory_info.lock()),
        creds: spin::Mutex::new(*parent.creds.lock()),
        io_stats: spin::Mutex::new(ProcessIoStats::default()),
        tty_nr: AtomicU32::new(parent.tty_nr.load(Ordering::Relaxed)),
        tty_pgrp: AtomicI32::new(parent.tty_pgrp.load(Ordering::Relaxed)),
        flags: AtomicU64::new(parent.flags.load(Ordering::Relaxed)),
        nice: AtomicI32::new(parent.nice.load(Ordering::Relaxed)),
        thread_count: AtomicU32::new(1),
        pending_signals: AtomicU64::new(0),
        kstkesp: AtomicU64::new(0),
        kstkeip: AtomicU64::new(0),
        wchan: AtomicU64::new(0),
        exit_signal: AtomicI32::new(17),
        processor: AtomicU32::new(0),
        rt_priority: AtomicU32::new(0),
        policy: AtomicU32::new(0),
        no_new_privs: AtomicU32::new(parent.no_new_privs.load(Ordering::Relaxed)),
        seccomp: AtomicU32::new(0),
        cpus_allowed: AtomicU64::new(!0),
        voluntary_switches: AtomicU64::new(0),
        involuntary_switches: AtomicU64::new(0),
        cr3: AtomicU64::new(0),
        io_bitmap: spin::Mutex::new([0xFF; 8192]),
        kernel_stack_top: AtomicU64::new(0),
        pending_user_entry: spin::Mutex::new(None),
        saved_user_context: spin::Mutex::new(None),
    });
    crate::process::address_space::lifecycle::inherit(&pcb, parent);
    Ok(pcb)
}

pub(crate) fn create_process_pcb(
    parent: &Arc<ProcessControlBlock>,
    pid: u32,
    name: &str,
    priority: Priority,
    caps: u64,
    pgid: u32,
    sid: u32,
    flags: u64,
) -> Result<Arc<ProcessControlBlock>, i32> {
    let memory = copy_memory(parent);
    let (argv, envp) = (parent.argv.lock().clone(), parent.envp.lock().clone());
    let (umask, root_dir, cwd) =
        (*parent.umask.lock(), parent.root_dir.lock().clone(), parent.cwd.lock().clone());
    let new_pgid = if (flags & CLONE_PARENT) != 0 { pgid } else { pid };
    let pcb = Arc::new(ProcessControlBlock {
        pid,
        tgid: AtomicU32::new(pid),
        ppid: AtomicU32::new(parent.pid),
        pgid: AtomicU32::new(new_pgid),
        sid: AtomicU32::new(sid),
        name: spin::Mutex::new(String::from(name)),
        state: spin::Mutex::new(ProcessState::Ready),
        priority: spin::Mutex::new(priority),
        memory: spin::Mutex::new(memory),
        thread_group: None,
        argv: spin::Mutex::new(argv),
        envp: spin::Mutex::new(envp),
        caps_bits: AtomicU64::new(caps),
        exit_code: AtomicI32::new(0),
        zk_proofs_generated: AtomicU64::new(0),
        zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0),
        zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0),
        umask: spin::Mutex::new(umask),
        root_dir: spin::Mutex::new(root_dir),
        cwd: spin::Mutex::new(cwd),
        clear_child_tid: AtomicU64::new(0),
        set_child_tid: AtomicU64::new(0),
        alarm_time_ms: AtomicU64::new(0),
        tls_base: AtomicU64::new(0),
        stack_base: AtomicU64::new(0),
        clone_flags: AtomicU64::new(flags),
        start_time_ms: AtomicU64::new(crate::time::timestamp_millis()),
        fd_table: parent.fd_table.fork(),
        signals: spin::Mutex::new(SignalState::default()),
        time_info: spin::Mutex::new(ProcessTimeInfo::default()),
        memory_info: spin::Mutex::new(*parent.memory_info.lock()),
        creds: spin::Mutex::new(*parent.creds.lock()),
        io_stats: spin::Mutex::new(ProcessIoStats::default()),
        tty_nr: AtomicU32::new(parent.tty_nr.load(Ordering::Relaxed)),
        tty_pgrp: AtomicI32::new(parent.tty_pgrp.load(Ordering::Relaxed)),
        flags: AtomicU64::new(0),
        nice: AtomicI32::new(0),
        thread_count: AtomicU32::new(1),
        pending_signals: AtomicU64::new(0),
        kstkesp: AtomicU64::new(0),
        kstkeip: AtomicU64::new(0),
        wchan: AtomicU64::new(0),
        exit_signal: AtomicI32::new(17),
        processor: AtomicU32::new(0),
        rt_priority: AtomicU32::new(0),
        policy: AtomicU32::new(0),
        no_new_privs: AtomicU32::new(parent.no_new_privs.load(Ordering::Relaxed)),
        seccomp: AtomicU32::new(0),
        cpus_allowed: AtomicU64::new(!0),
        voluntary_switches: AtomicU64::new(0),
        involuntary_switches: AtomicU64::new(0),
        cr3: AtomicU64::new(0),
        io_bitmap: spin::Mutex::new([0xFF; 8192]),
        kernel_stack_top: AtomicU64::new(0),
        pending_user_entry: spin::Mutex::new(None),
        saved_user_context: spin::Mutex::new(None),
    });
    crate::process::address_space::lifecycle::allocate(&pcb).map_err(|_| -1i32)?;
    Ok(pcb)
}
