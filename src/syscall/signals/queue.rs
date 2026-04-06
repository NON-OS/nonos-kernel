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

use super::state::{get_signal_state, set_signal_state};
use super::types::PendingSignal;
use alloc::vec::Vec;

pub const MAX_PENDING_SIGNALS: usize = 256;

pub fn queue_pending(pid: u32, signal: PendingSignal) -> Result<(), i32> {
    let mut state = get_signal_state(pid);
    if state.pending_queue.len() >= MAX_PENDING_SIGNALS {
        return Err(-12);
    }
    state.pending.add(signal.signo);
    state.pending_queue.push(signal);
    set_signal_state(pid, state);
    Ok(())
}

pub fn dequeue_pending(pid: u32, signo: u32) -> Option<PendingSignal> {
    let mut state = get_signal_state(pid);
    let pos = state.pending_queue.iter().position(|s| s.signo == signo)?;
    let signal = state.pending_queue.remove(pos);
    if !state.pending_queue.iter().any(|s| s.signo == signo) {
        state.pending.remove(signo);
    }
    set_signal_state(pid, state);
    Some(signal)
}

pub fn peek_pending(pid: u32) -> Option<PendingSignal> {
    let state = get_signal_state(pid);
    state.pending_queue.first().cloned()
}

pub fn pending_count(pid: u32) -> usize {
    let state = get_signal_state(pid);
    state.pending_queue.len()
}

pub fn clear_pending(pid: u32) -> usize {
    let mut state = get_signal_state(pid);
    let count = state.pending_queue.len();
    state.pending_queue.clear();
    state.pending = super::types::SigSet::new();
    set_signal_state(pid, state);
    count
}

pub fn get_pending_signals(pid: u32) -> Vec<u32> {
    let state = get_signal_state(pid);
    let mut signals = Vec::new();
    for sig in 1..=64 {
        if state.pending.contains(sig) {
            signals.push(sig);
        }
    }
    signals
}

pub fn has_pending_signal(pid: u32, signo: u32) -> bool {
    let state = get_signal_state(pid);
    state.pending.contains(signo)
}

pub fn queue_capacity_remaining(pid: u32) -> usize {
    let state = get_signal_state(pid);
    MAX_PENDING_SIGNALS.saturating_sub(state.pending_queue.len())
}

pub fn is_queue_full(pid: u32) -> bool {
    queue_capacity_remaining(pid) == 0
}

pub fn get_oldest_pending(pid: u32) -> Option<PendingSignal> {
    let state = get_signal_state(pid);
    state.pending_queue.iter().min_by_key(|s| s.timestamp).cloned()
}

pub fn remove_all_of_type(pid: u32, signo: u32) -> usize {
    let mut state = get_signal_state(pid);
    let before = state.pending_queue.len();
    state.pending_queue.retain(|s| s.signo != signo);
    state.pending.remove(signo);
    set_signal_state(pid, state);
    before - state.pending_queue.len()
}
