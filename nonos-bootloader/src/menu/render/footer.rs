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
use crate::display::gop::{fill_rect, get_dimensions};
use crate::menu::brand;
use crate::menu::types::MenuState;
use super::layout::MARGIN;

pub fn draw_panel_footer(state: &MenuState, x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, 1, brand::BORDER);
    draw_string(x, y + 16, b"[", brand::TEXT_MUTED); draw_string(x + 8, y + 16, b"^", brand::ACCENT_PRIMARY); draw_string(x + 16, y + 16, b"/", brand::TEXT_MUTED); draw_string(x + 24, y + 16, b"v", brand::ACCENT_PRIMARY);
    draw_string(x + 32, y + 16, b"] Navigate", brand::TEXT_MUTED); draw_string(x + 130, y + 16, b"[Enter] Select", brand::TEXT_MUTED);
    if state.timeout_ms > 0 { let secs = ((state.remaining_ms() + 999) / 1000) as u32; let msg = match secs { 0|1 => b"Auto-boot in 1s" as &[u8], 2 => b"Auto-boot in 2s", 3 => b"Auto-boot in 3s", 4 => b"Auto-boot in 4s", 5 => b"Auto-boot in 5s", _ => b"Auto-boot in 6s+" }; draw_string(x + (w - msg.len() as u32 * 8) / 2, y + 45, msg, brand::TEXT_SECONDARY); }
}

pub fn draw_bottom_bar(state: &MenuState) {
    let (sw, sh) = get_dimensions();
    let (bar_h, bar_y) = (50u32, sh - 50);
    fill_rect(0, bar_y, sw, bar_h, brand::BG_SECONDARY); fill_rect(0, bar_y, sw, 1, brand::BORDER);
    draw_string(MARGIN, bar_y + 18, b"Press F1 for help", brand::TEXT_MUTED);
    draw_string(sw - brand::VERSION.len() as u32 * 8 - MARGIN, bar_y + 18, brand::VERSION, brand::TEXT_MUTED);
    if state.timeout_ms > 0 { let (elapsed, pw) = (state.timeout_ms.saturating_sub(state.remaining_ms()), sw - MARGIN * 2); let filled = ((elapsed * pw as u64) / state.timeout_ms) as u32; fill_rect(MARGIN, bar_y - 6, pw, 4, brand::BORDER); if filled > 0 && filled <= pw { fill_rect(MARGIN, bar_y - 6, filled, 4, brand::ACCENT_PRIMARY); } }
}
