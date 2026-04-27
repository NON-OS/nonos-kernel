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

mod clone;
mod creds;
mod ids;
mod prctl;
mod wait;

pub use clone::{handle_clone, handle_clone3, handle_execveat};
pub use creds::{
    handle_capget, handle_capset, handle_getgroups, handle_getresgid, handle_getresuid,
    handle_setfsgid, handle_setfsuid, handle_setgid, handle_setgroups, handle_setregid,
    handle_setresgid, handle_setresuid, handle_setreuid, handle_setuid,
};
pub use ids::{
    handle_getegid, handle_geteuid, handle_getgid, handle_getpgid, handle_getpgrp,
    handle_getpid_extended, handle_getppid, handle_getsid, handle_gettid, handle_getuid,
    handle_setpgid, handle_setsid,
};
pub use prctl::{
    handle_arch_prctl, handle_getrandom, handle_prctl, handle_seccomp, handle_set_tid_address,
};
pub use wait::{handle_wait4, handle_waitid, record_child_exit};
