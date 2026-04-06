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

use alloc::collections::BTreeMap;
use spin::Mutex;

#[derive(Clone, Copy, Default)]
pub struct PtraceState {
    pub tracer_pid: u32,
    pub options: u32,
    pub event_msg: u64,
    pub syscall_entry: bool,
    pub singlestep: bool,
    pub seized: bool,
}

static PTRACE_STATE: Mutex<BTreeMap<u32, PtraceState>> = Mutex::new(BTreeMap::new());

pub fn is_traced(pid: u32) -> bool {
    PTRACE_STATE.lock().contains_key(&pid)
}

pub fn get_tracer(pid: u32) -> Option<u32> {
    PTRACE_STATE.lock().get(&pid).map(|s| s.tracer_pid)
}

pub fn get_state(pid: u32) -> Option<PtraceState> {
    PTRACE_STATE.lock().get(&pid).copied()
}

pub fn set_traced(pid: u32, tracer_pid: u32) {
    let mut map = PTRACE_STATE.lock();
    map.insert(pid, PtraceState { tracer_pid, ..Default::default() });
}

pub fn set_seized(pid: u32, tracer_pid: u32) {
    let mut map = PTRACE_STATE.lock();
    map.insert(pid, PtraceState { tracer_pid, seized: true, ..Default::default() });
}

pub fn clear_traced(pid: u32) {
    PTRACE_STATE.lock().remove(&pid);
}

pub fn set_options(pid: u32, options: u32) -> Result<(), i32> {
    let mut map = PTRACE_STATE.lock();
    let state = map.get_mut(&pid).ok_or(3)?;
    state.options = options;
    Ok(())
}

pub fn get_options(pid: u32) -> u32 {
    PTRACE_STATE.lock().get(&pid).map(|s| s.options).unwrap_or(0)
}

pub fn set_event_msg(pid: u32, msg: u64) {
    if let Some(state) = PTRACE_STATE.lock().get_mut(&pid) {
        state.event_msg = msg;
    }
}

pub fn get_event_msg(pid: u32) -> u64 {
    PTRACE_STATE.lock().get(&pid).map(|s| s.event_msg).unwrap_or(0)
}

pub fn set_singlestep(pid: u32, enabled: bool) {
    if let Some(state) = PTRACE_STATE.lock().get_mut(&pid) {
        state.singlestep = enabled;
    }
}

pub fn is_singlestep(pid: u32) -> bool {
    PTRACE_STATE.lock().get(&pid).map(|s| s.singlestep).unwrap_or(false)
}

pub fn set_syscall_entry(pid: u32, entry: bool) {
    if let Some(state) = PTRACE_STATE.lock().get_mut(&pid) {
        state.syscall_entry = entry;
    }
}

pub fn is_syscall_entry(pid: u32) -> bool {
    PTRACE_STATE.lock().get(&pid).map(|s| s.syscall_entry).unwrap_or(false)
}
