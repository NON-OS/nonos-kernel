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

const MARGIN: u32 = 30;
const HEADER_H: u32 = 32;
const ENTRY_H: u32 = 35;
const PAD: u32 = 16;

fn get_panel_bounds() -> (u32, u32, u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let x = (screen_w / 2) + (MARGIN / 2);
    let width = (screen_w / 2) - MARGIN - (MARGIN / 2);
    let content_x = x + PAD;
    let content_y = MARGIN + HEADER_H + PAD;
    (content_x, content_y, width - PAD * 2, screen_h - MARGIN * 2 - HEADER_H)
}

pub fn draw_logo() {
    let (screen_w, _) = get_dimensions();
    let logo_w = brand::LOGO[0].len() as u32 * 8;
    let x = (screen_w / 4) - (logo_w / 2);
    for (i, line) in brand::LOGO.iter().enumerate() {
        draw_string(x, 60 + i as u32 * 16, line, brand::ACCENT_PRIMARY);
    }
    let tagline_x = (screen_w / 4) - (brand::TAGLINE.len() as u32 * 4);
    draw_string(tagline_x, 160, brand::TAGLINE, brand::TEXT_SECONDARY);
}

pub fn render_menu(state: &MenuState) {
    if !state.visible { return; }
    let (cx, cy, cw, _ch) = get_panel_bounds();
    fill_rect(cx - PAD, cy - 8, cw + PAD * 2, 1, brand::ACCENT_SECONDARY);
    draw_string(cx, cy, b"Boot Mode Selection", brand::ACCENT_PRIMARY);
    fill_rect(cx, cy + 20, cw, 1, brand::ACCENT_SECONDARY);
    draw_entries(state, cx, cy + 32, cw);
    let footer_y = cy + 32 + (state.entries.len() as u32 * ENTRY_H) + 16;
    draw_footer(state, cx, footer_y, cw);
}

fn draw_entries(state: &MenuState, x: u32, y: u32, w: u32) {
    for (i, action) in state.entries.iter().enumerate() {
        let ey = y + (i as u32 * ENTRY_H);
        let selected = i == state.selected;
        let (bg, fg) = if selected {
            (brand::BG_CARD, brand::TEXT_PRIMARY)
        } else {
            (brand::BG_PRIMARY, brand::TEXT_MUTED)
        };
        fill_rect(x, ey, w, ENTRY_H - 2, bg);
        if selected { fill_rect(x, ey, 3, ENTRY_H - 2, brand::ACCENT_PRIMARY); }
        draw_string(x + 16, ey + 10, action.label().as_bytes(), fg);
    }
}

fn draw_footer(state: &MenuState, x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, 1, brand::ACCENT_SECONDARY);
    draw_string(x, y + 12, b"[Up/Down] Navigate", brand::TEXT_MUTED);
    draw_string(x + 170, y + 12, b"[Enter] Select", brand::TEXT_MUTED);
    if state.timeout_ms > 0 {
        let remaining = state.remaining_ms();
        let secs = ((remaining + 999) / 1000) as u32;
        draw_timer(x, y + 36, w, secs, state.timeout_ms, remaining);
    }
    let (screen_w, screen_h) = get_dimensions();
    fill_rect(0, screen_h - 50, screen_w, 50, brand::BG_SECONDARY);
    draw_string(20, screen_h - 35, b"Press F1 for help", brand::TEXT_MUTED);
    let ver_x = screen_w - brand::VERSION.len() as u32 * 8 - 20;
    draw_string(ver_x, screen_h - 35, brand::VERSION, brand::TEXT_MUTED);
}

fn draw_timer(x: u32, y: u32, w: u32, secs: u32, total_ms: u64, remaining_ms: u64) {
    let elapsed = total_ms.saturating_sub(remaining_ms);
    let progress = ((elapsed * w as u64) / total_ms) as u32;
    fill_rect(x, y, w, 4, brand::BORDER);
    if progress > 0 && progress <= w { fill_rect(x, y, progress, 4, brand::ACCENT_PRIMARY); }
    let msg: &[u8] = match secs {
        0 | 1 => b"Auto-boot in 1 second",
        2 => b"Auto-boot in 2 seconds",
        3 => b"Auto-boot in 3 seconds",
        4 => b"Auto-boot in 4 seconds",
        5 => b"Auto-boot in 5 seconds",
        _ => b"Auto-boot in 6+ seconds",
    };
    draw_string(x, y + 10, msg, brand::TEXT_MUTED);
}

pub fn clear_menu_area() {
    let (cx, cy, cw, ch) = get_panel_bounds();
    fill_rect(cx - PAD, cy - 8, cw + PAD * 2, ch, brand::BG_PRIMARY);
}

pub fn clear_screen() {
    let (w, h) = get_dimensions();
    fill_rect(0, 0, w, h, brand::BG_PRIMARY);
}
