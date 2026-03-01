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
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::types::ProcessSignalState;

pub static SIGNAL_STATE: RwLock<BTreeMap<u32, ProcessSignalState>> =
    RwLock::new(BTreeMap::new());

pub static SIGNAL_STATS: SignalStats = SignalStats::new();

pub struct SignalStats {
    pub signals_sent: AtomicU64,
    pub signals_delivered: AtomicU64,
    pub signals_ignored: AtomicU64,
    pub signals_blocked: AtomicU64,
}

impl SignalStats {
    pub const fn new() -> Self {
        SignalStats {
            signals_sent: AtomicU64::new(0),
            signals_delivered: AtomicU64::new(0),
            signals_ignored: AtomicU64::new(0),
            signals_blocked: AtomicU64::new(0),
        }
    }
}

pub fn get_signal_state(pid: u32) -> ProcessSignalState {
    let state_map = SIGNAL_STATE.read();
    state_map.get(&pid).cloned().unwrap_or_default()
}

pub fn set_signal_state(pid: u32, state: ProcessSignalState) {
    SIGNAL_STATE.write().insert(pid, state);
}

pub fn get_signal_stats() -> (u64, u64, u64, u64) {
    (
        SIGNAL_STATS.signals_sent.load(Ordering::Relaxed),
        SIGNAL_STATS.signals_delivered.load(Ordering::Relaxed),
        SIGNAL_STATS.signals_ignored.load(Ordering::Relaxed),
        SIGNAL_STATS.signals_blocked.load(Ordering::Relaxed),
    )
}

pub fn init_process_signals(pid: u32) {
    set_signal_state(pid, ProcessSignalState::default());
}

pub fn cleanup_process_signals(pid: u32) {
    SIGNAL_STATE.write().remove(&pid);
}

pub fn has_pending() -> bool {
    let pid = match crate::process::current_pid() {
        Some(p) => p,
        None => return false,
    };
    let state_map = SIGNAL_STATE.read();
    if let Some(state) = state_map.get(&pid) {
        let deliverable = state.pending & !state.blocked;
        deliverable != 0
    } else {
        false
    }
}
