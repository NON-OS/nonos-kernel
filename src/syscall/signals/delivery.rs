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

use core::sync::atomic::Ordering;

use crate::syscall::SyscallResult;
use super::constants::*;
use super::types::*;
use super::state::*;

#[inline]
fn errno(e: i32) -> SyscallResult {
    SyscallResult { value: -(e as i64), capability_consumed: false, audit_required: true }
}

pub fn send_signal(pid: u32, sig: u32) -> SyscallResult {
    if sig == 0 {
        if crate::process::get_process_table().find_by_pid(pid).is_some() {
            return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
        } else {
            return errno(3);
        }
    }

    if sig > SIGRTMAX {
        return errno(22);
    }

    if crate::process::get_process_table().find_by_pid(pid).is_none() {
        return errno(3);
    }

    SIGNAL_STATS.signals_sent.fetch_add(1, Ordering::Relaxed);

    let sender_pid = crate::process::current_pid().unwrap_or(0);

    let pending = PendingSignal {
        signo: sig,
        code: 0,
        pid: sender_pid,
        uid: 0,
        value: 0,
        timestamp: crate::time::timestamp_millis(),
    };

    queue_signal(pid, pending)
}

pub fn queue_signal(pid: u32, signal: PendingSignal) -> SyscallResult {
    let mut state = get_signal_state(pid);
    let sig = signal.signo;

    let action = &state.actions[sig as usize];

    if action.handler == SIG_IGN && sig != SIGCHLD {
        SIGNAL_STATS.signals_ignored.fetch_add(1, Ordering::Relaxed);
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    if state.blocked.contains(sig) && sig != SIGKILL && sig != SIGSTOP {
        SIGNAL_STATS.signals_blocked.fetch_add(1, Ordering::Relaxed);
        state.pending.add(sig);
        state.pending_queue.push(signal);
        set_signal_state(pid, state);
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    state.pending.add(sig);
    state.pending_queue.push(signal);
    set_signal_state(pid, state);

    try_deliver_signals(pid);

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn try_deliver_signals(pid: u32) {
    let mut state = get_signal_state(pid);

    let deliverable = state.pending.0 & !state.blocked.0;
    if deliverable == 0 {
        return;
    }

    for sig in 1..=SIGRTMAX {
        if !state.pending.contains(sig) {
            continue;
        }
        if state.blocked.contains(sig) && sig != SIGKILL && sig != SIGSTOP {
            continue;
        }

        let action = state.actions[sig as usize];

        let siginfo = state.pending_queue.iter()
            .position(|s| s.signo == sig)
            .map(|i| state.pending_queue.remove(i));

        if sig < SIGRTMIN {
            state.pending.remove(sig);
        }

        SIGNAL_STATS.signals_delivered.fetch_add(1, Ordering::Relaxed);

        match action.handler {
            SIG_DFL => {
                handle_default_signal(pid, sig, siginfo.as_ref());
            }
            SIG_IGN => {
            }
            _handler => {
                handle_user_signal(pid, sig, &action, siginfo.as_ref(), &mut state);
            }
        }
    }

    set_signal_state(pid, state);
}

fn handle_default_signal(pid: u32, sig: u32, _info: Option<&PendingSignal>) {
    match sig {
        SIGHUP | SIGINT | SIGKILL | SIGPIPE | SIGALRM | SIGTERM |
        SIGPOLL | SIGPROF | SIGUSR1 | SIGUSR2 | SIGVTALRM => {
            terminate_process(pid, sig);
        }

        SIGQUIT | SIGILL | SIGABRT | SIGFPE | SIGSEGV | SIGBUS |
        SIGSYS | SIGTRAP | SIGXCPU | SIGXFSZ => {
            crate::log::log_warning!("Process {} terminated by signal {} (core dump)", pid, sig);
            terminate_process(pid, sig);
        }

        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
            stop_process(pid);
        }

        SIGCONT => {
            continue_process(pid);
        }

        SIGCHLD | SIGURG | SIGWINCH => {
        }

        _ if sig >= SIGRTMIN && sig <= SIGRTMAX => {
            terminate_process(pid, sig);
        }

        _ => {}
    }
}

fn handle_user_signal(
    pid: u32,
    sig: u32,
    action: &KernelSigAction,
    _info: Option<&PendingSignal>,
    state: &mut ProcessSignalState,
) {
    state.saved_mask = Some(state.blocked);

    state.blocked.0 |= action.mask.0;

    if (action.flags & SA_NODEFER) == 0 {
        state.blocked.add(sig);
    }

    crate::log::debug!("Signal {} delivered to pid {} (handler at 0x{:x})",
                       sig, pid, action.handler);
}

fn terminate_process(pid: u32, sig: u32) {
    if let Some(pcb) = crate::process::get_process_table().find_by_pid(pid) {
        let exit_status = 128 + sig as i32;

        crate::process::accounting::record_exit_from_pcb(&pcb, exit_status, true);

        pcb.terminate(exit_status);
        crate::log::info!("Process {} terminated by signal {}", pid, sig);
    }
}

fn stop_process(pid: u32) {
    let _ = crate::process::suspend_process(pid);
    crate::log::debug!("Process {} stopped", pid);
}

fn continue_process(pid: u32) {
    let _ = crate::process::nonos_core::resume_process(pid);
    crate::log::debug!("Process {} continued", pid);
}
