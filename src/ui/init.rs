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

use super::{cli, clipboard, event, gui, keyboard};

pub fn init_ui_subsystems() -> Result<(), &'static str> {
    event::init_event_bus();
    cli::init_cli(64);
    clipboard::init_clipboard();
    keyboard::init_keyboard();
    Ok(())
}

pub fn create_window(title: &str, x: i32, y: i32, width: u32, height: u32) -> Result<u32, &'static str> {
    gui::request_create_window(title, x, y, width, height)
}
