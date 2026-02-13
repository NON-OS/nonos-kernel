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

mod format;
mod utf16;

pub use format::{
    format_boot_progress, format_fail, format_hash_short, format_hex_bytes, format_log_message,
    format_log_message_with_tick, format_memory_size, format_ok, format_skip, format_status,
};
pub use utf16::{
    format_log_line, format_log_line_with_tick, utf8_to_utf16, Utf16Buffer, UTF16_BUFFER_SIZE,
};
