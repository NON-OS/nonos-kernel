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

mod api;
mod close;
mod poll;
mod registry;
mod stats;
mod types;

pub use api::{create_pipe, create_pipe_with_size, pipe_read, pipe_write};
pub use close::{pipe_close, pipe_set_nonblock};
pub use poll::{fd_to_pipe_id, get_pipe_internal_id, is_pipe};
pub use poll::{get_pipe_info, pipe_is_readable, pipe_is_writable, PipeInfo};
pub use stats::{get_pipe_stats, pipe_count, PipeStats};
pub use types::PIPE_BUF_SIZE;
