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

use crate::display::font::draw_string;
use crate::display::log_panel::LogLevel;
use super::frame::TerminalLayout;

const LINE_HEIGHT: u32 = 18;
const COLOR_INFO: u32 = 0xFF6B7280;
const COLOR_OK: u32 = 0xFF00FF88;
const COLOR_WARN: u32 = 0xFFFFAA00;
const COLOR_ERROR: u32 = 0xFFFF4444;
const COLOR_SECURITY: u32 = 0xFF66FFFF;

pub fn render_terminal_content(layout: &TerminalLayout, entries: &[TerminalEntry]) {
    let max_lines = layout.max_visible_lines();
    let start = if entries.len() > max_lines { entries.len() - max_lines } else { 0 };

    for (i, entry) in entries[start..].iter().enumerate() {
        let y = layout.content_y + (i as u32 * LINE_HEIGHT);
        render_line(layout.content_x, y, entry);
    }
}

fn render_line(x: u32, y: u32, entry: &TerminalEntry) {
    let (prefix, color) = match entry.level {
        LogLevel::Info => (b"    " as &[u8], COLOR_INFO),
        LogLevel::Ok => (b"[+] " as &[u8], COLOR_OK),
        LogLevel::Warn => (b"[!] " as &[u8], COLOR_WARN),
        LogLevel::Error => (b"[X] " as &[u8], COLOR_ERROR),
        LogLevel::Security => (b"[S] " as &[u8], COLOR_SECURITY),
    };

    draw_string(x, y, prefix, color);
    draw_string(x + 32, y, entry.text, color);
}

pub struct TerminalEntry<'a> {
    pub level: LogLevel,
    pub text: &'a [u8],
}

impl<'a> TerminalEntry<'a> {
    pub fn new(level: LogLevel, text: &'a [u8]) -> Self {
        Self { level, text }
    }
}
