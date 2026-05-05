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

use crate::process::signal::constants::*;
use crate::process::{current_pid, terminate_current_with_signal, with_process_mut, ProcessState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Terminate,
    CoreDump,
    Stop,
    Continue,
    Ignore,
}

pub fn default_action(signo: u8) -> DefaultAction {
    match signo {
        SIGHUP | SIGINT | SIGKILL | SIGUSR1 | SIGUSR2 | SIGPIPE | SIGALRM | SIGTERM | SIGSTKFLT
        | SIGVTALRM | SIGPROF | SIGIO | SIGPWR => DefaultAction::Terminate,
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGXCPU | SIGXFSZ
        | SIGSYS => DefaultAction::CoreDump,
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        n if n >= SIGRTMIN && n <= SIGRTMAX => DefaultAction::Terminate,
        _ => DefaultAction::Ignore,
    }
}

pub fn perform_default(pid: u32, signo: u8) {
    match default_action(signo) {
        DefaultAction::Terminate | DefaultAction::CoreDump => {
            if current_pid() == Some(pid) {
                terminate_current_with_signal(signo);
            }
            crate::process::exit::teardown(pid, signo as i32 + 128, true);
        }
        DefaultAction::Stop => {
            with_process_mut(pid, |pcb| {
                *pcb.state.lock() = ProcessState::Stopped;
            });
        }
        DefaultAction::Continue => {
            with_process_mut(pid, |pcb| {
                let mut state = pcb.state.lock();
                if matches!(*state, ProcessState::Stopped) {
                    *state = ProcessState::Ready;
                }
            });
        }
        DefaultAction::Ignore => {}
    }
}
