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
use super::types::SigSet;

pub fn get_pending_mask(pid: u32) -> SigSet {
    get_signal_state(pid).pending
}

pub fn set_pending_mask(pid: u32, mask: SigSet) {
    let mut state = get_signal_state(pid);
    state.pending = mask;
    set_signal_state(pid, state);
}

pub fn add_pending(pid: u32, signo: u32) {
    let mut state = get_signal_state(pid);
    state.pending.add(signo);
    set_signal_state(pid, state);
}

pub fn remove_pending(pid: u32, signo: u32) {
    let mut state = get_signal_state(pid);
    state.pending.remove(signo);
    set_signal_state(pid, state);
}

pub fn is_pending(pid: u32, signo: u32) -> bool {
    get_signal_state(pid).pending.contains(signo)
}

pub fn any_pending(pid: u32) -> bool {
    !get_signal_state(pid).pending.is_empty()
}

pub fn get_deliverable(pid: u32) -> SigSet {
    let state = get_signal_state(pid);
    let blocked = state.blocked;
    let pending = state.pending;
    SigSet(pending.0 & !blocked.0)
}

pub fn any_deliverable(pid: u32) -> bool {
    !get_deliverable(pid).is_empty()
}

pub fn first_deliverable(pid: u32) -> Option<u32> {
    let deliverable = get_deliverable(pid);
    for sig in 1..=64 {
        if deliverable.contains(sig) {
            return Some(sig);
        }
    }
    None
}

pub fn count_pending(pid: u32) -> usize {
    let pending = get_pending_mask(pid);
    let mut count = 0;
    for sig in 1..=64 {
        if pending.contains(sig) {
            count += 1;
        }
    }
    count
}

pub fn count_deliverable(pid: u32) -> usize {
    let deliverable = get_deliverable(pid);
    let mut count = 0;
    for sig in 1..=64 {
        if deliverable.contains(sig) {
            count += 1;
        }
    }
    count
}

pub fn clear_all_pending(pid: u32) {
    let mut state = get_signal_state(pid);
    state.pending = SigSet::new();
    state.pending_queue.clear();
    set_signal_state(pid, state);
}

pub fn pending_for_current() -> SigSet {
    let pid = crate::process::current_pid().unwrap_or(0);
    get_pending_mask(pid)
}

pub fn deliverable_for_current() -> SigSet {
    let pid = crate::process::current_pid().unwrap_or(0);
    get_deliverable(pid)
}
