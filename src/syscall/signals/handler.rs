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

use super::constants::*;
use super::state::{get_signal_state, set_signal_state};
use super::types::{KernelSigAction, SigSet};

pub fn get_handler(pid: u32, signo: u32) -> u64 {
    if signo == 0 || signo > 64 {
        return SIG_DFL;
    }
    let state = get_signal_state(pid);
    state.actions[signo as usize].handler
}

pub fn set_handler(pid: u32, signo: u32, handler: u64) -> Result<u64, i32> {
    if signo == 0 || signo > 64 {
        return Err(-22);
    }
    if signo == SIGKILL || signo == SIGSTOP {
        return Err(-22);
    }
    let mut state = get_signal_state(pid);
    let old = state.actions[signo as usize].handler;
    state.actions[signo as usize].handler = handler;
    set_signal_state(pid, state);
    Ok(old)
}

pub fn get_action(pid: u32, signo: u32) -> Option<KernelSigAction> {
    if signo == 0 || signo > 64 {
        return None;
    }
    let state = get_signal_state(pid);
    Some(state.actions[signo as usize])
}

pub fn set_action(pid: u32, signo: u32, action: KernelSigAction) -> Result<KernelSigAction, i32> {
    if signo == 0 || signo > 64 {
        return Err(-22);
    }
    if signo == SIGKILL || signo == SIGSTOP {
        return Err(-22);
    }
    let mut state = get_signal_state(pid);
    let old = state.actions[signo as usize];
    state.actions[signo as usize] = action;
    set_signal_state(pid, state);
    Ok(old)
}

pub fn is_ignored(pid: u32, signo: u32) -> bool {
    get_handler(pid, signo) == SIG_IGN
}

pub fn is_default(pid: u32, signo: u32) -> bool {
    get_handler(pid, signo) == SIG_DFL
}

pub fn is_caught(pid: u32, signo: u32) -> bool {
    let handler = get_handler(pid, signo);
    handler != SIG_DFL && handler != SIG_IGN
}

pub fn reset_to_default(pid: u32, signo: u32) -> Result<(), i32> {
    set_handler(pid, signo, SIG_DFL)?;
    Ok(())
}

pub fn ignore_signal(pid: u32, signo: u32) -> Result<(), i32> {
    set_handler(pid, signo, SIG_IGN)?;
    Ok(())
}

pub fn reset_all_handlers(pid: u32) {
    let mut state = get_signal_state(pid);
    for i in 1..=64 {
        if i != SIGKILL && i != SIGSTOP {
            state.actions[i as usize] = KernelSigAction::default();
        }
    }
    set_signal_state(pid, state);
}

pub fn get_handler_mask(pid: u32, signo: u32) -> SigSet {
    if signo == 0 || signo > 64 {
        return SigSet::new();
    }
    let state = get_signal_state(pid);
    state.actions[signo as usize].mask
}

pub fn set_handler_mask(pid: u32, signo: u32, mask: SigSet) -> Result<(), i32> {
    if signo == 0 || signo > 64 {
        return Err(-22);
    }
    let mut state = get_signal_state(pid);
    state.actions[signo as usize].mask = mask;
    set_signal_state(pid, state);
    Ok(())
}

pub fn copy_handlers_from_parent(child_pid: u32, parent_pid: u32) {
    let parent_state = get_signal_state(parent_pid);
    let mut child_state = get_signal_state(child_pid);
    child_state.actions = parent_state.actions;
    set_signal_state(child_pid, child_state);
}
