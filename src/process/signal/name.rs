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

pub fn signal_name(signo: u8) -> &'static str {
    match signo {
        SIGHUP => "SIGHUP",
        SIGINT => "SIGINT",
        SIGQUIT => "SIGQUIT",
        SIGILL => "SIGILL",
        SIGTRAP => "SIGTRAP",
        SIGABRT => "SIGABRT",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGUSR1 => "SIGUSR1",
        SIGSEGV => "SIGSEGV",
        SIGUSR2 => "SIGUSR2",
        SIGPIPE => "SIGPIPE",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        SIGSTKFLT => "SIGSTKFLT",
        SIGCHLD => "SIGCHLD",
        SIGCONT => "SIGCONT",
        SIGSTOP => "SIGSTOP",
        SIGTSTP => "SIGTSTP",
        SIGTTIN => "SIGTTIN",
        SIGTTOU => "SIGTTOU",
        SIGURG => "SIGURG",
        SIGXCPU => "SIGXCPU",
        SIGXFSZ => "SIGXFSZ",
        SIGVTALRM => "SIGVTALRM",
        SIGPROF => "SIGPROF",
        SIGWINCH => "SIGWINCH",
        SIGIO => "SIGIO",
        SIGPWR => "SIGPWR",
        SIGSYS => "SIGSYS",
        n if n >= SIGRTMIN && n <= SIGRTMAX => "SIGRT",
        _ => "UNKNOWN",
    }
}

pub fn signal_from_name(name: &str) -> Option<u8> {
    match name {
        "SIGHUP" | "HUP" => Some(SIGHUP),
        "SIGINT" | "INT" => Some(SIGINT),
        "SIGQUIT" | "QUIT" => Some(SIGQUIT),
        "SIGILL" | "ILL" => Some(SIGILL),
        "SIGTRAP" | "TRAP" => Some(SIGTRAP),
        "SIGABRT" | "ABRT" => Some(SIGABRT),
        "SIGBUS" | "BUS" => Some(SIGBUS),
        "SIGFPE" | "FPE" => Some(SIGFPE),
        "SIGKILL" | "KILL" => Some(SIGKILL),
        "SIGUSR1" | "USR1" => Some(SIGUSR1),
        "SIGSEGV" | "SEGV" => Some(SIGSEGV),
        "SIGUSR2" | "USR2" => Some(SIGUSR2),
        "SIGPIPE" | "PIPE" => Some(SIGPIPE),
        "SIGALRM" | "ALRM" => Some(SIGALRM),
        "SIGTERM" | "TERM" => Some(SIGTERM),
        "SIGSTKFLT" | "STKFLT" => Some(SIGSTKFLT),
        "SIGCHLD" | "CHLD" => Some(SIGCHLD),
        "SIGCONT" | "CONT" => Some(SIGCONT),
        "SIGSTOP" | "STOP" => Some(SIGSTOP),
        "SIGTSTP" | "TSTP" => Some(SIGTSTP),
        "SIGTTIN" | "TTIN" => Some(SIGTTIN),
        "SIGTTOU" | "TTOU" => Some(SIGTTOU),
        "SIGURG" | "URG" => Some(SIGURG),
        "SIGXCPU" | "XCPU" => Some(SIGXCPU),
        "SIGXFSZ" | "XFSZ" => Some(SIGXFSZ),
        "SIGVTALRM" | "VTALRM" => Some(SIGVTALRM),
        "SIGPROF" | "PROF" => Some(SIGPROF),
        "SIGWINCH" | "WINCH" => Some(SIGWINCH),
        "SIGIO" | "IO" | "SIGPOLL" | "POLL" => Some(SIGIO),
        "SIGPWR" | "PWR" => Some(SIGPWR),
        "SIGSYS" | "SYS" => Some(SIGSYS),
        _ => None,
    }
}
