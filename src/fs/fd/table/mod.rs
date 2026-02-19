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

mod core;
mod flags;
mod dup;
mod status;
mod truncate;
mod cloexec;

pub use self::core::{
    validate_fd_range, is_stdio, get_entry_read, get_entry_write,
    fd_is_valid, fd_open, fd_open_raw, fd_close, fd_get_path, fd_get_offset, fd_stats,
};
pub use flags::{fd_set_cloexec, fd_get_cloexec, fd_get_flags, fd_set_flags, fd_set_nonblocking};
pub use dup::{fd_dup_min, fd_dup, fd_dup2};
pub use status::{fd_has_data, fd_can_write, fd_is_closed_remote, fd_bytes_available, fd_is_writable};
pub use truncate::fd_truncate;
pub use cloexec::fd_close_cloexec;
