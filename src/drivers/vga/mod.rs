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
pub mod buffer;
pub mod color;
pub mod constants;
pub mod error;
pub mod io;

#[cfg(test)]
mod tests;

pub use api::{
    clear, clear_region, disable_cursor, enable_cursor, flush_cursor, get_color, get_cursor,
    get_size, init_vga, put_char, set_auto_cursor_update, set_color, set_cursor, try_write_str,
    write_at, write_str, write_str_at,
};
pub use buffer::VgaCell;
pub use color::{decode_color, vga_color, Color, DEFAULT_BG, DEFAULT_COLOR, DEFAULT_FG};
pub use constants::{VGA_BUFFER_ADDR, VGA_HEIGHT, VGA_TOTAL_CELLS, VGA_WIDTH};
