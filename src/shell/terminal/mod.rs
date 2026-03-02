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

pub mod renderer;
pub mod buffer;
pub mod history;
pub mod input;
pub mod completion;
mod operations;

pub use renderer::*;
pub use buffer::get_buffer;
pub use history::{get_history, add_command as history_add, secure_erase as history_erase};
pub use input::{get_editor, handle_key};
pub use completion::{complete as tab_complete, reset as completion_reset};
pub use operations::*;

pub fn init() {
    renderer::init();
    buffer::init();
    history::init();
    input::init();
    operations::init_state();
}

pub fn term_x() -> u32 {
    renderer::term_x()
}

pub fn term_y() -> u32 {
    renderer::term_y()
}
