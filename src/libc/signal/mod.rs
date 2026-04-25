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

pub mod handlers;

pub use handlers::{kill, raise, sigaction, sigemptyset, sigfillset, signal, sigprocmask};
pub use handlers::{sigaddset, sigdelset, sigismember, sigpending, sigsuspend};
pub use handlers::{SigAction, SigInfo, Sigset, SIG_DFL, SIG_ERR, SIG_IGN};
pub use handlers::{SIGABRT, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGKILL, SIGQUIT, SIGSEGV};
pub use handlers::{SIGALRM, SIGCHLD, SIGCONT, SIGPIPE, SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2};
