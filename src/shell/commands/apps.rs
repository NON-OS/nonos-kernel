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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_ACCENT};
use crate::graphics::window::{self, WindowType};

pub fn cmd_apps() {
    print_line(b"Installed Applications:", COLOR_TEXT);
    print_line(b"===================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [1] browser       Web Browser", COLOR_ACCENT);
    print_line(b"      Tor-routed browsing", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [2] files         File Manager", COLOR_ACCENT);
    print_line(b"      RAM filesystem browser", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [3] editor        Text Editor", COLOR_ACCENT);
    print_line(b"      Edit files in RAM", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [4] calc          Calculator", COLOR_ACCENT);
    print_line(b"      Basic arithmetic", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [5] settings      System Config", COLOR_ACCENT);
    print_line(b"      Privacy & Security", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [6] monitor       Process Manager", COLOR_ACCENT);
    print_line(b"      System processes", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [7] wallet        Crypto Wallet", COLOR_ACCENT);
    print_line(b"      Ethereum & stealth addresses", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  [8] about         About N\xd8NOS", COLOR_ACCENT);
    print_line(b"      System information", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"Type app name to launch (e.g. browser)", COLOR_GREEN);
}

fn cmd_open_app(wtype: WindowType, app_name: &[u8]) {
    window::open(wtype);

    let mut buf = [0u8; 64];
    buf[0..8].copy_from_slice(b"Opened: ");
    let name_len = app_name.len().min(32);
    buf[8..8+name_len].copy_from_slice(&app_name[..name_len]);
    print_line(&buf[..8+name_len], COLOR_GREEN);

    // SAFETY: NEEDS_REDRAW is a global flag accessed from the main thread only.
    // The shell runs single-threaded, so no concurrent access occurs. This flag
    // signals to the main event loop that the window system needs a redraw.
    unsafe {
        crate::NEEDS_REDRAW = true;
    }
}

pub fn cmd_open_browser() {
    cmd_open_app(WindowType::Browser, b"Browser");
}

pub fn cmd_open_files() {
    cmd_open_app(WindowType::FileManager, b"Files");
}

pub fn cmd_open_editor() {
    cmd_open_app(WindowType::TextEditor, b"Editor");
}

pub fn cmd_open_calculator() {
    cmd_open_app(WindowType::Calculator, b"Calculator");
}

pub fn cmd_open_settings() {
    cmd_open_app(WindowType::Settings, b"Settings");
}

pub fn cmd_open_monitor() {
    cmd_open_app(WindowType::ProcessManager, b"Monitor");
}

pub fn cmd_open_wallet() {
    cmd_open_app(WindowType::Wallet, b"Wallet");
}
