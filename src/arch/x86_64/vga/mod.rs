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
//! x86_64 VGA Text Mode Driver.

mod api;
pub mod constants;
pub mod console;
pub mod cursor;
pub mod error;
pub mod ops;
mod state;

#[cfg(test)]
mod tests;

pub use api::print;
pub use constants::*;
pub use console::Console;
pub use cursor::{disable_cursor, enable_cursor, update_cursor};
pub use error::VgaError;
pub use ops::{
    active_console, clear, enter_panic_mode, get_stats, init, is_initialized, print_critical,
    print_hex, set_color, switch_console, write_byte, write_str, write_str_to_console, VgaStats,
    VgaWriter,
};
