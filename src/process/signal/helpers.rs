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

use super::constants::{SIGKILL, SIGRTMAX, SIGRTMIN, SIGSTOP};

pub fn is_valid_signal(signo: u8) -> bool {
    signo >= 1 && signo <= SIGRTMAX
}

pub fn is_rt_signal(signo: u8) -> bool {
    signo >= SIGRTMIN && signo <= SIGRTMAX
}

pub fn can_be_caught(signo: u8) -> bool {
    signo != SIGKILL && signo != SIGSTOP
}

pub fn can_be_ignored(signo: u8) -> bool {
    signo != SIGKILL && signo != SIGSTOP
}

pub fn can_be_blocked(signo: u8) -> bool {
    signo != SIGKILL && signo != SIGSTOP
}

pub fn is_synchronous(signo: u8) -> bool {
    use super::constants::*;
    matches!(signo, SIGILL | SIGTRAP | SIGBUS | SIGFPE | SIGSEGV | SIGSYS)
}

pub fn is_stop_signal(signo: u8) -> bool {
    use super::constants::*;
    matches!(signo, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

pub fn is_fatal_by_default(signo: u8) -> bool {
    use super::constants::*;
    matches!(
        signo,
        SIGHUP
            | SIGINT
            | SIGQUIT
            | SIGILL
            | SIGABRT
            | SIGFPE
            | SIGKILL
            | SIGSEGV
            | SIGPIPE
            | SIGALRM
            | SIGTERM
            | SIGUSR1
            | SIGUSR2
            | SIGBUS
            | SIGPOLL
            | SIGPROF
            | SIGSYS
            | SIGTRAP
            | SIGVTALRM
            | SIGXCPU
            | SIGXFSZ
            | SIGSTKFLT
    )
}

pub fn generates_core_dump(signo: u8) -> bool {
    use super::constants::*;
    matches!(
        signo,
        SIGQUIT
            | SIGILL
            | SIGABRT
            | SIGFPE
            | SIGSEGV
            | SIGBUS
            | SIGSYS
            | SIGTRAP
            | SIGXCPU
            | SIGXFSZ
    )
}
