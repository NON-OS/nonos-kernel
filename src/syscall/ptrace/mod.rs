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

mod types;
mod state;
mod attach;
mod memory;
mod regs;
mod control;
mod syscall;

pub use types::{PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_DETACH, PTRACE_CONT};
pub use types::{PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_KILL};
pub use types::{PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_POKETEXT, PTRACE_POKEDATA};
pub use types::{PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG};
pub use types::{PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEFORK, PTRACE_O_TRACEEXEC};
pub use types::{PTRACE_EVENT_FORK, PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT};
pub use types::UserRegsStruct;
pub use state::{is_traced, get_tracer, set_traced, clear_traced, set_event_msg};
pub use syscall::{handle_ptrace, ptrace_report_syscall_entry, ptrace_report_syscall_exit};
pub use attach::{do_traceme, do_attach, do_detach};
pub use control::{do_cont, do_singlestep, do_kill};
