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

use crate::display::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM};
use crate::shell::output::print_line;

pub use super::apps_open::*;

pub fn cmd_apps() {
    print_line(b"Installed Applications:", COLOR_TEXT);
    print_line(b"===================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  browser       Web Browser (NYM Mixnet)", COLOR_ACCENT);
    print_line(b"  files         File Manager", COLOR_ACCENT);
    print_line(b"  editor        Text Editor", COLOR_ACCENT);
    print_line(b"  calc          Calculator", COLOR_ACCENT);
    print_line(b"  settings      System Config", COLOR_ACCENT);
    print_line(b"  monitor       Process Manager", COLOR_ACCENT);
    print_line(b"  wallet        Crypto Wallet", COLOR_ACCENT);
    print_line(b"  marketplace   NOX App Store", COLOR_ACCENT);
    print_line(b"  agents        AI Agents", COLOR_ACCENT);
    print_line(b"  about         About N\xd8NOS", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Type app name to launch", COLOR_GREEN);
}
