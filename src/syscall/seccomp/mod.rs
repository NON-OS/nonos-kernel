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
mod filter;
mod state;
mod check;
mod syscall;
mod load;

pub use types::{SECCOMP_MODE_DISABLED, SECCOMP_MODE_STRICT, SECCOMP_MODE_FILTER};
pub use types::{SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER};
pub use types::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ERRNO};
pub use types::{SeccompData, SockFilter, SockFprog};
pub use filter::SeccompFilter;
pub use state::{get_mode, set_strict_mode, add_filter, clone_seccomp, clear_seccomp};
pub use check::{check_syscall, is_allowed, SeccompResult};
pub use syscall::handle_seccomp;
pub use load::{load_filter_from_user, create_allow_all_filter, create_syscall_whitelist};
