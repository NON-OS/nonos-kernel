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
use crate::menu::types::MenuState;

const MARGIN: u32 = 30;
const HEADER_H: u32 = 32;
const ENTRY_H: u32 = 28;
const PAD: u32 = 16;

const BG_ENTRY: u32 = 0x101820;
const BG_SELECT: u32 = 0x1A3040;
const BORDER_DIM: u32 = 0x2E5C5C;
const COL_TITLE: u32 = 0x66FFFF;
const COL_TEXT: u32 = 0xE8E8F0;
const COL_DIM: u32 = 0x707080;
const COL_ACCENT: u32 = 0x66FFFF;

fn get_right_panel_bounds() -> (u32, u32, u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let x = (screen_w / 2) + (MARGIN / 2);
    let width = (screen_w / 2) - MARGIN - (MARGIN / 2);
    let content_x = x + PAD;
    let content_y = MARGIN + HEADER_H + PAD;
    (content_x, content_y, width - PAD * 2, screen_h - MARGIN * 2 - HEADER_H)
}

pub fn render_menu(state: &MenuState) {
    if !state.visible {
        return;
    }

    let (cx, cy, cw, _ch) = get_right_panel_bounds();

    draw_string(cx, cy, b"Boot Mode Selection", COL_TITLE);
    fill_rect(cx, cy + 20, cw, 1, BORDER_DIM);

    let entries_y = cy + 32;
    draw_entries(state, cx, entries_y, cw);

    let n = state.entries.len() as u32;
    let footer_y = entries_y + (n * ENTRY_H) + 16;
    draw_footer(state, cx, footer_y, cw);
}

fn draw_entries(state: &MenuState, x: u32, y: u32, w: u32) {
    for (i, action) in state.entries.iter().enumerate() {
        let ey = y + (i as u32 * ENTRY_H);
        let selected = i == state.selected;
        let bg = if selected { BG_SELECT } else { BG_ENTRY };
        let text_color = if selected { COL_TEXT } else { COL_DIM };

        fill_rect(x, ey, w, ENTRY_H - 2, bg);

        if selected {
            fill_rect(x, ey, 3, ENTRY_H - 2, COL_ACCENT);
        }

        draw_string(x + 12, ey + 6, action.label().as_bytes(), text_color);
    }
}

fn draw_footer(state: &MenuState, x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, 1, BORDER_DIM);

    draw_string(x, y + 10, b"[Up/Down] Navigate", COL_DIM);
    draw_string(x + 160, y + 10, b"[Enter] Select", COL_DIM);

    if state.timeout_ms > 0 {
        let remaining = state.remaining_ms();
        let secs = ((remaining + 999) / 1000) as u32;
        draw_timer(x, y + 32, w, secs, state.timeout_ms, remaining);
    }
}

fn draw_timer(x: u32, y: u32, w: u32, secs: u32, total_ms: u64, remaining_ms: u64) {
    let elapsed = total_ms.saturating_sub(remaining_ms);
    let progress = ((elapsed * w as u64) / total_ms) as u32;

    fill_rect(x, y, w, 4, BORDER_DIM);
    if progress > 0 && progress <= w {
        fill_rect(x, y, progress, 4, COL_ACCENT);
    }

    let msg: &[u8] = match secs {
        0 | 1 => b"Auto-boot in 1 second",
        2 => b"Auto-boot in 2 seconds",
        3 => b"Auto-boot in 3 seconds",
        4 => b"Auto-boot in 4 seconds",
        5 => b"Auto-boot in 5 seconds",
        _ => b"Auto-boot in 6+ seconds",
    };

    draw_string(x, y + 10, msg, COL_DIM);
}

pub fn clear_menu_area() {
    let (cx, cy, cw, ch) = get_right_panel_bounds();
    crate::display::background::render_region(cx, cy, cw, ch);
}
