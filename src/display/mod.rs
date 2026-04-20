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

mod error;
mod framebuffer;
pub mod text;
pub mod font;

pub use error::DisplayError;
pub use framebuffer::{Framebuffer, FramebufferInfo, register_framebuffer, get_framebuffer};
pub use framebuffer::{write_pixel, fill_rect, clear};
pub use text::{write_char, write_string, clear_screen};

#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
pub mod tests;
