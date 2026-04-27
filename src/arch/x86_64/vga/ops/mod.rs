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

pub mod console;
pub mod init;
pub mod lock;
pub mod stats;
pub mod write;

pub use console::{active_console, switch_console, VgaWriter};
pub use init::{enter_panic_mode, init, is_initialized};
pub use stats::{get_stats, VgaStats};
pub use write::{
    clear, print_critical, print_hex, set_color, write_byte, write_str, write_str_to_console,
};
