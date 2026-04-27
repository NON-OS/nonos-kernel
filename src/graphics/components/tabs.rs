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

use crate::graphics::design_system::{borders, colors};
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, rounded_rect_blend};

pub const TAB_HEIGHT: u32 = 40;
pub const TAB_PADDING: u32 = 16;
pub const TAB_GAP: u32 = 4;

#[derive(Clone, Copy, PartialEq)]
pub enum TabStyle {
    Underline,
    Pill,
    Glass,
}

pub fn draw_tab_bar(x: u32, y: u32, w: u32, tabs: &[&[u8]], selected: usize, style: TabStyle) {
    let tab_w = calc_tab_widths(tabs, w);
    let mut tx = x;
    for (i, label) in tabs.iter().enumerate() {
        let is_selected = i == selected;
        draw_tab(tx, y, tab_w[i], *label, is_selected, style);
        tx += tab_w[i] + TAB_GAP;
    }
    if style == TabStyle::Underline {
        fill_rect(x, y + TAB_HEIGHT - 1, w, 1, colors::BORDER_DEFAULT);
    }
}

fn draw_tab(x: u32, y: u32, w: u32, label: &[u8], selected: bool, style: TabStyle) {
    match style {
        TabStyle::Underline => draw_tab_underline(x, y, w, label, selected),
        TabStyle::Pill => draw_tab_pill(x, y, w, label, selected),
        TabStyle::Glass => draw_tab_glass(x, y, w, label, selected),
    }
}

fn draw_tab_underline(x: u32, y: u32, w: u32, label: &[u8], selected: bool) {
    let text_color = if selected { colors::ACCENT } else { colors::TEXT_SECONDARY };
    let text_x = x + (w - label.len() as u32 * 8) / 2;
    draw_text(text_x, y + 12, label, text_color);
    if selected {
        fill_rect(x, y + TAB_HEIGHT - 2, w, 2, colors::ACCENT);
    }
}

fn draw_tab_pill(x: u32, y: u32, w: u32, label: &[u8], selected: bool) {
    if selected {
        rounded_rect_blend(x, y + 4, w, TAB_HEIGHT - 8, borders::RADIUS_MD, colors::ACCENT);
    }
    let text_color = if selected { colors::TEXT_INVERSE } else { colors::TEXT_SECONDARY };
    let text_x = x + (w - label.len() as u32 * 8) / 2;
    draw_text(text_x, y + 12, label, text_color);
}

fn draw_tab_glass(x: u32, y: u32, w: u32, label: &[u8], selected: bool) {
    let bg = if selected { colors::GLASS_BG_ACTIVE } else { 0 };
    if selected {
        rounded_rect_blend(x, y + 4, w, TAB_HEIGHT - 8, borders::RADIUS_MD, bg);
    }
    let text_color = if selected { colors::ACCENT } else { colors::TEXT_SECONDARY };
    let text_x = x + (w - label.len() as u32 * 8) / 2;
    draw_text(text_x, y + 12, label, text_color);
}

fn calc_tab_widths(tabs: &[&[u8]], total_w: u32) -> [u32; 16] {
    let mut widths = [0u32; 16];
    let count = tabs.len().min(16);
    let gap_total = if count > 1 { (count - 1) as u32 * TAB_GAP } else { 0 };
    let available = total_w.saturating_sub(gap_total);
    let per_tab = available / count as u32;
    for i in 0..count {
        widths[i] = per_tab;
    }
    widths
}

pub fn tab_hit_test(
    x: u32,
    tabs: &[&[u8]],
    total_w: u32,
    click_x: i32,
    click_y: i32,
    bar_y: u32,
) -> i32 {
    if click_y < bar_y as i32 || click_y >= (bar_y + TAB_HEIGHT) as i32 {
        return -1;
    }
    let widths = calc_tab_widths(tabs, total_w);
    let mut tx = x as i32;
    for i in 0..tabs.len().min(16) {
        if click_x >= tx && click_x < tx + widths[i] as i32 {
            return i as i32;
        }
        tx += widths[i] as i32 + TAB_GAP as i32;
    }
    -1
}
