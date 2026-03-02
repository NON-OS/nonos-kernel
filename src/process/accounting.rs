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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

#[derive(Clone, Debug)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exit_code: i32,
    pub start_time_ms: u64,
    pub end_time_ms: u64,
    pub elapsed_ms: u64,
    pub peak_memory_kb: u64,
    pub capabilities: u64,
    pub signaled: bool,
    pub clone_flags: u64,
}

impl ProcessRecord {
    pub fn new(pid: u32, ppid: u32, name: &str) -> Self {
        Self {
            pid,
            ppid,
            name: String::from(name),
            exit_code: 0,
            start_time_ms: 0,
            end_time_ms: 0,
            elapsed_ms: 0,
            peak_memory_kb: 0,
            capabilities: 0,
            signaled: false,
            clone_flags: 0,
        }
    }

    pub fn format(&self) -> String {
        alloc::format!(
            "[{}] {} (ppid={}) exit={} elapsed={}ms mem={}KB caps={:016x}{}",
            self.pid,
            self.name,
            self.ppid,
            self.exit_code,
            self.elapsed_ms,
            self.peak_memory_kb,
            self.capabilities,
            if self.signaled { " [SIGNALED]" } else { "" }
        )
    }
}

struct AccountingState {
    enabled: AtomicBool,
    records: Mutex<Vec<ProcessRecord>>,
    max_records: AtomicU64,
    total_recorded: AtomicU64,
}

impl AccountingState {
    const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            records: Mutex::new(Vec::new()),
            max_records: AtomicU64::new(1000),
            total_recorded: AtomicU64::new(0),
        }
    }
}

static ACCOUNTING: AccountingState = AccountingState::new();

pub fn enable_accounting(_path: &str) -> Result<(), &'static str> {
    ACCOUNTING.enabled.store(true, Ordering::SeqCst);
    crate::log::info!("NONOS process accounting enabled");
    Ok(())
}

pub fn disable_accounting() {
    ACCOUNTING.enabled.store(false, Ordering::SeqCst);
    crate::log::info!("NONOS process accounting disabled");
}

pub fn is_accounting_enabled() -> bool {
    ACCOUNTING.enabled.load(Ordering::Relaxed)
}

pub fn get_accounting_stats() -> (u64, u64, u64) {
    let records = ACCOUNTING.records.lock();
    (
        ACCOUNTING.total_recorded.load(Ordering::Relaxed),
        records.len() as u64,
        ACCOUNTING.max_records.load(Ordering::Relaxed),
    )
}

pub fn set_max_records(max: u64) {
    ACCOUNTING.max_records.store(max, Ordering::Relaxed);
}

pub fn record_process_exit(
    pid: u32,
    ppid: u32,
    _uid: u32,
    _gid: u32,
    exit_code: i32,
    command: &str,
    start_time_ms: u64,
    _user_time_ms: u64,
    _sys_time_ms: u64,
    memory_kb: u64,
    _was_forked: bool,
    _was_superuser: bool,
    _dumped_core: bool,
    killed_by_signal: bool,
) {
    if !ACCOUNTING.enabled.load(Ordering::Relaxed) {
        return;
    }

    let now_ms = crate::time::timestamp_millis();
    let elapsed_ms = now_ms.saturating_sub(start_time_ms);

    let record = ProcessRecord {
        pid,
        ppid,
        name: String::from(command),
        exit_code,
        start_time_ms,
        end_time_ms: now_ms,
        elapsed_ms,
        peak_memory_kb: memory_kb,
        capabilities: 0,
        signaled: killed_by_signal,
        clone_flags: 0,
    };

    let mut records = ACCOUNTING.records.lock();
    let max = ACCOUNTING.max_records.load(Ordering::Relaxed) as usize;

    while records.len() >= max && !records.is_empty() {
        records.remove(0);
    }

    records.push(record);
    ACCOUNTING.total_recorded.fetch_add(1, Ordering::Relaxed);
}

pub fn record_exit_from_pcb(pcb: &super::ProcessControlBlock, exit_code: i32, was_signaled: bool) {
    if !ACCOUNTING.enabled.load(Ordering::Relaxed) {
        return;
    }

    let name = pcb.name.lock();
    let pid = pcb.pid;
    let ppid = pcb.parent_pid();
    let start_time_ms = pcb.start_time_ms.load(Ordering::Relaxed);

    if start_time_ms == 0 {
        return;
    }

    let now_ms = crate::time::timestamp_millis();
    let elapsed_ms = now_ms.saturating_sub(start_time_ms);

    let memory_kb = {
        let memory = pcb.memory.lock();
        memory.resident_pages.load(Ordering::Relaxed) * 4
    };

    let record = ProcessRecord {
        pid,
        ppid,
        name: name.clone(),
        exit_code,
        start_time_ms,
        end_time_ms: now_ms,
        elapsed_ms,
        peak_memory_kb: memory_kb,
        capabilities: pcb.caps_bits.load(Ordering::Relaxed),
        signaled: was_signaled,
        clone_flags: pcb.clone_flags.load(Ordering::Relaxed),
    };

    let mut records = ACCOUNTING.records.lock();
    let max = ACCOUNTING.max_records.load(Ordering::Relaxed) as usize;

    while records.len() >= max && !records.is_empty() {
        records.remove(0);
    }

    records.push(record);
    ACCOUNTING.total_recorded.fetch_add(1, Ordering::Relaxed);
}

pub fn get_recent_records(count: usize) -> Vec<ProcessRecord> {
    let records = ACCOUNTING.records.lock();
    let start = records.len().saturating_sub(count);
    records[start..].to_vec()
}

pub fn get_all_records() -> Vec<ProcessRecord> {
    ACCOUNTING.records.lock().clone()
}

pub fn clear_records() {
    ACCOUNTING.records.lock().clear();
}

pub fn find_by_pid(pid: u32) -> Vec<ProcessRecord> {
    ACCOUNTING.records.lock()
        .iter()
        .filter(|r| r.pid == pid)
        .cloned()
        .collect()
}

pub use super::acct_record::{AcctRecord, AFORK, ASU, ACORE, AXSIG};
