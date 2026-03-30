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

mod color;
mod helpers;
mod vga_cell;
mod log_level;
mod stats;

pub use color::Color;
pub(crate) use helpers::{make_color, fg_from_attr, bg_from_attr, set_fg, set_bg};
pub use vga_cell::VgaCell;
pub use log_level::LogLevel;
pub use stats::{ConsoleStats, ConsoleStatsSnapshot};
