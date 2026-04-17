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

const MARGIN: u32 = 40;
const PANEL_WIDTH: u32 = 320;
const ENTRY_H: u32 = 40;
const PAD: u32 = 20;

fn get_panel_bounds() -> (u32, u32, u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let panel_x = screen_w - PANEL_WIDTH - MARGIN;
    let panel_y = MARGIN;
    let panel_h = screen_h - MARGIN * 2 - 60;
    (panel_x, panel_y, PANEL_WIDTH, panel_h)
}

pub fn draw_logo() {
    let (screen_w, _) = get_dimensions();
    let logo_w = brand::LOGO[0].len() as u32 * 8;
    let center_x = (screen_w - PANEL_WIDTH - MARGIN * 2) / 2;
    let x = center_x.saturating_sub(logo_w / 2);
    for (i, line) in brand::LOGO.iter().enumerate() {
        draw_string(x, 80 + i as u32 * 18, line, brand::ACCENT_PRIMARY);
    }
    let tagline_w = brand::TAGLINE.len() as u32 * 8;
    let tagline_x = center_x.saturating_sub(tagline_w / 2);
    draw_string(tagline_x, 190, brand::TAGLINE, brand::TEXT_SECONDARY);
}

pub fn render_menu(state: &MenuState) {
    if !state.visible { return; }
    let (px, py, pw, _ph) = get_panel_bounds();
    draw_panel_background(px, py, pw);
    draw_panel_header(px, py, pw);
    let entries_y = py + 70;
    draw_entries(state, px + PAD, entries_y, pw - PAD * 2);
    let footer_y = entries_y + (state.entries.len() as u32 * ENTRY_H) + 30;
    draw_panel_footer(state, px + PAD, footer_y, pw - PAD * 2);
    draw_bottom_bar(state);
}

fn draw_panel_background(x: u32, y: u32, w: u32) {
    let (_, screen_h) = get_dimensions();
    let h = screen_h - y - MARGIN - 60;
    fill_rect(x, y, w, h, brand::BG_CARD);
    fill_rect(x, y, w, 3, brand::ACCENT_PRIMARY);
    fill_rect(x, y, 1, h, brand::BORDER);
    fill_rect(x + w - 1, y, 1, h, brand::BORDER);
    fill_rect(x, y + h - 1, w, 1, brand::BORDER);
}

fn draw_panel_header(x: u32, y: u32, w: u32) {
    draw_string(x + PAD, y + 20, b"Boot Options", brand::ACCENT_PRIMARY);
    fill_rect(x + PAD, y + 50, w - PAD * 2, 1, brand::BORDER);
}

fn draw_entries(state: &MenuState, x: u32, y: u32, w: u32) {
    for (i, action) in state.entries.iter().enumerate() {
        let ey = y + (i as u32 * ENTRY_H);
        let selected = i == state.selected;
        let (bg, fg) = if selected {
            (brand::BG_SECONDARY, brand::TEXT_PRIMARY)
        } else {
            (brand::BG_CARD, brand::TEXT_MUTED)
        };
        fill_rect(x, ey, w, ENTRY_H - 4, bg);
        if selected {
            fill_rect(x, ey, 4, ENTRY_H - 4, brand::ACCENT_PRIMARY);
        }
        let label = action.label();
        draw_string(x + 20, ey + 12, label.as_bytes(), fg);
    }
}

fn draw_panel_footer(state: &MenuState, x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, 1, brand::BORDER);
    draw_string(x, y + 16, b"[", brand::TEXT_MUTED);
    draw_string(x + 8, y + 16, b"^", brand::ACCENT_PRIMARY);
    draw_string(x + 16, y + 16, b"/", brand::TEXT_MUTED);
    draw_string(x + 24, y + 16, b"v", brand::ACCENT_PRIMARY);
    draw_string(x + 32, y + 16, b"] Navigate", brand::TEXT_MUTED);
    draw_string(x + 130, y + 16, b"[Enter] Select", brand::TEXT_MUTED);
    if state.timeout_ms > 0 {
        let remaining = state.remaining_ms();
        let secs = ((remaining + 999) / 1000) as u32;
        draw_timeout_indicator(x, y + 45, w, secs);
    }
}

fn draw_timeout_indicator(x: u32, y: u32, w: u32, secs: u32) {
    let msg = match secs {
        0 | 1 => b"Auto-boot in 1s",
        2 => b"Auto-boot in 2s",
        3 => b"Auto-boot in 3s",
        4 => b"Auto-boot in 4s",
        5 => b"Auto-boot in 5s",
        _ => b"Auto-boot in 6s+",
    };
    let msg_w = msg.len() as u32 * 8;
    draw_string(x + (w - msg_w) / 2, y, msg, brand::TEXT_SECONDARY);
}

fn draw_bottom_bar(state: &MenuState) {
    let (screen_w, screen_h) = get_dimensions();
    let bar_h = 50;
    let bar_y = screen_h - bar_h;
    fill_rect(0, bar_y, screen_w, bar_h, brand::BG_SECONDARY);
    fill_rect(0, bar_y, screen_w, 1, brand::BORDER);
    draw_string(MARGIN, bar_y + 18, b"Press F1 for help", brand::TEXT_MUTED);
    let ver_w = brand::VERSION.len() as u32 * 8;
    draw_string(screen_w - ver_w - MARGIN, bar_y + 18, brand::VERSION, brand::TEXT_MUTED);
    if state.timeout_ms > 0 {
        let remaining = state.remaining_ms();
        let elapsed = state.timeout_ms.saturating_sub(remaining);
        let progress_w = screen_w - MARGIN * 2;
        let filled = ((elapsed * progress_w as u64) / state.timeout_ms) as u32;
        let progress_y = bar_y - 6;
        fill_rect(MARGIN, progress_y, progress_w, 4, brand::BORDER);
        if filled > 0 && filled <= progress_w {
            fill_rect(MARGIN, progress_y, filled, 4, brand::ACCENT_PRIMARY);
        }
    }
}

pub fn clear_menu_area() {
    let (px, py, pw, ph) = get_panel_bounds();
    fill_rect(px, py, pw, ph, brand::BG_PRIMARY);
}

pub fn clear_screen() {
    let (w, h) = get_dimensions();
    fill_rect(0, 0, w, h, brand::BG_PRIMARY);
}
