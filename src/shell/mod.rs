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

pub mod commands;
pub mod editor;
mod init;
pub mod output;
pub mod script;
pub mod terminal;

#[cfg(test)]
#[cfg(test)]
pub mod tests;

pub use commands::*;
pub use init::init;
pub use output::{disable_gui_output, enable_gui_output, print_line as unified_print};
pub use terminal::*;

pub fn execute_and_capture(cmd: &[u8]) -> alloc::vec::Vec<u8> {
    commands::pipeline::start_capture();
    commands::execute_for_gui(cmd);
    commands::pipeline::stop_capture()
}
