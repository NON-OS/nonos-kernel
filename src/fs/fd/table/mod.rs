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

mod cloexec;
mod core;
mod dup;
mod flags;
mod open;
mod query;
mod status;
mod truncate;

pub use self::core::{get_entry_read, get_entry_write, is_stdio, validate_fd_range};
pub use cloexec::fd_close_cloexec;
pub use dup::{fd_dup, fd_dup2, fd_dup_min};
pub use flags::{fd_get_cloexec, fd_get_flags, fd_set_cloexec, fd_set_flags, fd_set_nonblocking};
pub use open::{fd_close, fd_open, fd_open_raw};
pub use query::{fd_get_offset, fd_get_path, fd_is_valid, fd_stats};
pub use status::{
    fd_bytes_available, fd_can_write, fd_has_data, fd_is_closed_remote, fd_is_writable,
};
pub use truncate::fd_truncate;
