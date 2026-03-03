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

mod ansi;
mod api;
mod constants;
pub mod error;
mod macros;
mod types;
mod vga;
mod writer;

#[cfg(test)]
mod tests;

pub use ansi::{apply_sgr, AnsiAction, AnsiParser, ParserState};
pub use api::{
    clear, get_console_stats, get_stats_snapshot, init_console, print, printf, println, set_color,
    write_message,
};
pub use constants::*;
pub use types::{Color, ConsoleStats, ConsoleStatsSnapshot, LogLevel, VgaCell};
