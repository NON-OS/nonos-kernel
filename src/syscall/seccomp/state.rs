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

use super::filter::SeccompFilter;
use super::types::{SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Clone)]
pub struct SeccompState {
    pub mode: u32,
    pub filters: Vec<SeccompFilter>,
}

impl Default for SeccompState {
    fn default() -> Self {
        Self { mode: SECCOMP_MODE_DISABLED, filters: Vec::new() }
    }
}

static PROCESS_SECCOMP: Mutex<BTreeMap<u32, SeccompState>> = Mutex::new(BTreeMap::new());

pub fn get_mode(pid: u32) -> u32 {
    PROCESS_SECCOMP.lock().get(&pid).map(|s| s.mode).unwrap_or(SECCOMP_MODE_DISABLED)
}

pub fn set_strict_mode(pid: u32) -> Result<(), i32> {
    let mut map = PROCESS_SECCOMP.lock();
    let state = map.entry(pid).or_default();
    if state.mode != SECCOMP_MODE_DISABLED {
        return Err(1);
    }
    state.mode = SECCOMP_MODE_STRICT;
    crate::security::monitoring::audit::log_security_event(
        "seccomp",
        crate::security::monitoring::audit::AuditSeverity::Info,
        alloc::format!("Process {} entered strict seccomp mode", pid),
        Some(pid as u64),
        None,
        None,
    );
    Ok(())
}

pub fn add_filter(pid: u32, filter: SeccompFilter) -> Result<(), i32> {
    filter.validate()?;
    let mut map = PROCESS_SECCOMP.lock();
    let state = map.entry(pid).or_default();
    if state.mode == SECCOMP_MODE_STRICT {
        return Err(1);
    }
    state.mode = SECCOMP_MODE_FILTER;
    let filter_count = state.filters.len() + 1;
    state.filters.push(filter);
    crate::security::monitoring::audit::log_security_event(
        "seccomp",
        crate::security::monitoring::audit::AuditSeverity::Info,
        alloc::format!("Process {} installed seccomp filter #{}", pid, filter_count),
        Some(pid as u64),
        None,
        None,
    );
    Ok(())
}

pub fn log_seccomp_violation(pid: u32, syscall_nr: u64, action: u32) {
    crate::security::monitoring::audit::log_security_event(
        "seccomp",
        crate::security::monitoring::audit::AuditSeverity::Warning,
        alloc::format!(
            "Process {} seccomp violation: syscall {} action {:#x}",
            pid,
            syscall_nr,
            action
        ),
        Some(pid as u64),
        None,
        Some(alloc::vec![alloc::format!("syscall:{}", syscall_nr)]),
    );
}

pub fn get_filters(pid: u32) -> Vec<SeccompFilter> {
    PROCESS_SECCOMP.lock().get(&pid).map(|s| s.filters.clone()).unwrap_or_default()
}

pub fn clone_seccomp(parent_pid: u32, child_pid: u32) {
    let map = PROCESS_SECCOMP.lock();
    if let Some(parent_state) = map.get(&parent_pid) {
        let mut map = PROCESS_SECCOMP.lock();
        map.insert(child_pid, parent_state.clone());
    }
}

pub fn clear_seccomp(pid: u32) {
    PROCESS_SECCOMP.lock().remove(&pid);
}

pub fn filter_count(pid: u32) -> usize {
    PROCESS_SECCOMP.lock().get(&pid).map(|s| s.filters.len()).unwrap_or(0)
}
