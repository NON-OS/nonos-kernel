// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::render_helpers::{draw_string, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM};

pub fn draw_empty_browser_help(x: u32, content_y: u32) {
    draw_string(x + 20, content_y + 20, b"Enter a URL to browse the web", COLOR_TEXT_DIM);
    draw_string(x + 20, content_y + 44, b"Privacy features enabled:", COLOR_TEXT);
    draw_string(x + 20, content_y + 68, b"  - Tracker blocking", COLOR_ACCENT);
    draw_string(x + 20, content_y + 92, b"  - URL parameter stripping", COLOR_ACCENT);
    draw_string(x + 20, content_y + 116, b"  - JavaScript disabled by default", COLOR_ACCENT);
    draw_string(x + 20, content_y + 156, b"Keyboard shortcuts:", COLOR_TEXT);
    draw_string(x + 20, content_y + 180, b"  Page Up/Down - Scroll page", COLOR_TEXT_DIM);
    draw_string(x + 20, content_y + 204, b"  Enter - Navigate to URL", COLOR_TEXT_DIM);
}
