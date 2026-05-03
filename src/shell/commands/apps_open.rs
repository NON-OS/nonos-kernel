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

use crate::entry::desktop_loop::set_needs_redraw;
use crate::display::framebuffer::COLOR_GREEN;
use crate::graphics::window::{self, WindowType};
use crate::shell::output::print_line;

fn open_app(wtype: WindowType, name: &[u8]) {
    window::open(wtype);
    let mut buf = [0u8; 64];
    buf[0..8].copy_from_slice(b"Opened: ");
    let len = name.len().min(32);
    buf[8..8 + len].copy_from_slice(&name[..len]);
    print_line(&buf[..8 + len], COLOR_GREEN);
    set_needs_redraw();
}

pub fn cmd_open_browser() {
    open_app(WindowType::Browser, b"Browser");
}
pub fn cmd_open_files() {
    open_app(WindowType::FileManager, b"Files");
}
pub fn cmd_open_editor() {
    open_app(WindowType::TextEditor, b"Editor");
}
pub fn cmd_open_calculator() {
    open_app(WindowType::Calculator, b"Calculator");
}
pub fn cmd_open_settings() {
    open_app(WindowType::Settings, b"Settings");
}
pub fn cmd_open_monitor() {
    open_app(WindowType::ProcessManager, b"Monitor");
}
pub fn cmd_open_wallet() {
    open_app(WindowType::Wallet, b"Wallet");
}
pub fn cmd_open_marketplace() {
    open_app(WindowType::Marketplace, b"Marketplace");
}
pub fn cmd_open_agents() {
    open_app(WindowType::Agents, b"Agents");
}
