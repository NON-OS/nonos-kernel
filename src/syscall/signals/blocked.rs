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

use super::constants::{SIGKILL, SIGSTOP};
use super::state::{get_signal_state, set_signal_state};
use super::types::SigSet;

pub fn get_blocked_mask(pid: u32) -> SigSet {
    get_signal_state(pid).blocked
}

pub fn set_blocked_mask(pid: u32, mask: SigSet) {
    let mut state = get_signal_state(pid);
    state.blocked = sanitize_mask(mask);
    set_signal_state(pid, state);
}

pub fn block_signal(pid: u32, signo: u32) -> Result<(), i32> {
    if signo == SIGKILL || signo == SIGSTOP {
        return Err(-22);
    }
    let mut state = get_signal_state(pid);
    state.blocked.add(signo);
    set_signal_state(pid, state);
    Ok(())
}

pub fn unblock_signal(pid: u32, signo: u32) {
    let mut state = get_signal_state(pid);
    state.blocked.remove(signo);
    set_signal_state(pid, state);
}

pub fn is_blocked(pid: u32, signo: u32) -> bool {
    get_signal_state(pid).blocked.contains(signo)
}

pub fn block_all_except_kill_stop(pid: u32) {
    let mut state = get_signal_state(pid);
    state.blocked = SigSet::full();
    state.blocked.remove(SIGKILL);
    state.blocked.remove(SIGSTOP);
    set_signal_state(pid, state);
}

pub fn unblock_all(pid: u32) {
    let mut state = get_signal_state(pid);
    state.blocked = SigSet::new();
    set_signal_state(pid, state);
}

fn sanitize_mask(mut mask: SigSet) -> SigSet {
    mask.remove(SIGKILL);
    mask.remove(SIGSTOP);
    mask
}

pub fn sigprocmask(pid: u32, how: i32, set: &SigSet) -> Result<SigSet, i32> {
    let mut state = get_signal_state(pid);
    let old = state.blocked;
    match how {
        0 => state.blocked.0 |= set.0,
        1 => state.blocked.0 &= !set.0,
        2 => state.blocked = *set,
        _ => return Err(-22),
    }
    state.blocked = sanitize_mask(state.blocked);
    set_signal_state(pid, state);
    Ok(old)
}

pub fn save_mask(pid: u32) {
    let mut state = get_signal_state(pid);
    state.saved_mask = Some(state.blocked);
    set_signal_state(pid, state);
}

pub fn restore_mask(pid: u32) {
    let mut state = get_signal_state(pid);
    if let Some(saved) = state.saved_mask.take() {
        state.blocked = saved;
    }
    set_signal_state(pid, state);
}

pub fn blocked_for_current() -> SigSet {
    let pid = crate::process::current_pid().unwrap_or(0);
    get_blocked_mask(pid)
}

pub fn count_blocked(pid: u32) -> usize {
    let blocked = get_blocked_mask(pid);
    let mut count = 0;
    for sig in 1..=64 {
        if blocked.contains(sig) {
            count += 1;
        }
    }
    count
}
