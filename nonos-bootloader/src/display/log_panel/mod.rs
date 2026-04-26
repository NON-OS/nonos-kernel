// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
pub mod buffer;
pub mod entry;
mod format;
mod helpers;
pub mod render;
pub mod types;

pub use api::{clear, log, log_error, log_info, log_ok, log_security, log_warn, refresh};
pub use buffer::{get_cursor_y, init_log_timer};
pub use entry::LogEntry;
pub use format::{log_hash, log_hash_full, log_hex, log_mem, log_size, log_u32};
pub use render::redraw_all;
pub use types::LogLevel;
