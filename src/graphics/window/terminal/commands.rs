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

use core::sync::atomic::Ordering;
use crate::shell::output::{enable_gui_output, disable_gui_output};
use super::state::add_to_history;
use super::buffer::{clear_screen, starts_with};

pub(super) fn execute_command(cmd: &[u8]) {
    if cmd.is_empty() {
        return;
    }

    add_to_history(cmd);

    if starts_with(cmd, b"clear") {
        clear_screen();
        return;
    } else if starts_with(cmd, b"exit") {
        let focused = crate::graphics::window::state::FOCUSED_WINDOW.load(Ordering::Relaxed);
        crate::graphics::window::manager::close(focused);
        return;
    }

    enable_gui_output(0);
    crate::shell::commands::execute_for_gui(cmd);
    disable_gui_output();
}
