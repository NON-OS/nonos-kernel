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

mod state;
mod colors;
mod primitives;
pub mod double_buffer;

pub use state::init;
pub(crate) use state::dimensions;
pub use colors::*;
pub use primitives::{get_pixel, put_pixel, fill_rect, clear, hline, vline, draw_rect, fill_rounded_rect};
pub use double_buffer::{init_double_buffer, swap_buffers};

pub fn is_double_buffer_enabled() -> bool {
    double_buffer::is_enabled()
}
