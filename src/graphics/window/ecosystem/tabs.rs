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

use super::state::EcosystemTab;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::font::draw_char;

pub const TAB_HEIGHT: u32 = 36;
pub const TAB_MIN_WIDTH: u32 = 80;
pub const TAB_PADDING: u32 = 16;

pub const COLOR_TAB_BAR: u32 = 0xFF161B22;
pub const COLOR_TAB_ACTIVE: u32 = 0xFF238636;
pub const COLOR_TAB_HOVER: u32 = 0xFF21262D;
pub const COLOR_TAB_TEXT: u32 = 0xFFC9D1D9;
pub const COLOR_TAB_TEXT_ACTIVE: u32 = 0xFFFFFFFF;
pub const COLOR_TAB_BORDER: u32 = 0xFF30363D;

pub struct TabLayout {
    pub tabs: [(u32, u32, u32); 6],
    pub total_width: u32,
}

pub fn calculate_layout(available_width: u32) -> TabLayout {
    let tab_count = EcosystemTab::count();
    let total_padding = TAB_PADDING * 2 * tab_count as u32;
    let content_width = available_width.saturating_sub(16).saturating_sub(total_padding / 8);

    let mut tab_widths = [0u32; 6];
    for i in 0..tab_count {
        let tab = EcosystemTab::from_u8(i as u8);
        let label_width = tab.label().len() as u32 * 8;
        tab_widths[i] = (label_width + TAB_PADDING * 2).max(TAB_MIN_WIDTH);
    }

    let total_natural_width: u32 = tab_widths.iter().sum();

    if total_natural_width > content_width {
        let scale = content_width as f32 / total_natural_width as f32;
        for w in tab_widths.iter_mut() {
            *w = ((*w as f32 * scale) as u32).max(40);
        }
    }

    let mut tabs = [(0u32, 0u32, 0u32); 6];
    let mut x = 8u32;

    for i in 0..tab_count {
        tabs[i] = (x, tab_widths[i], TAB_HEIGHT);
        x += tab_widths[i];
    }

    TabLayout {
        tabs,
        total_width: x,
    }
}

pub fn draw_tab_bar(x: u32, y: u32, w: u32, active: EcosystemTab) {
    fill_rect(x, y, w, TAB_HEIGHT, COLOR_TAB_BAR);

    fill_rect(x, y + TAB_HEIGHT - 1, w, 1, COLOR_TAB_BORDER);

    let layout = calculate_layout(w);

    for i in 0..EcosystemTab::count() {
        let tab = EcosystemTab::from_u8(i as u8);
        let (tab_x, tab_w, _) = layout.tabs[i];
        let is_active = tab == active;

        draw_tab(x + tab_x, y + 4, tab_w, TAB_HEIGHT - 8, tab, is_active);
    }
}

fn draw_tab(x: u32, y: u32, w: u32, h: u32, tab: EcosystemTab, active: bool) {
    let bg_color = if active {
        COLOR_TAB_ACTIVE
    } else {
        COLOR_TAB_HOVER
    };

    if active {
        fill_rect(x, y, w, h, bg_color);
        draw_rounded_corners(x, y, w, h, bg_color);
    }

    let label = tab.label();
    let text_color = if active {
        COLOR_TAB_TEXT_ACTIVE
    } else {
        COLOR_TAB_TEXT
    };

    let label_width = label.len() as u32 * 8;
    let text_x = x + (w.saturating_sub(label_width)) / 2;
    let text_y = y + (h.saturating_sub(16)) / 2;

    for (i, &ch) in label.iter().enumerate() {
        draw_char(text_x + i as u32 * 8, text_y, ch, text_color);
    }
}

fn draw_rounded_corners(x: u32, y: u32, w: u32, h: u32, tint: u32) {
    use crate::graphics::framebuffer::put_pixel;

    let bg = if tint > 0 { tint } else { COLOR_TAB_BAR };

    put_pixel(x, y, bg);
    put_pixel(x + 1, y, bg);
    put_pixel(x, y + 1, bg);

    put_pixel(x + w - 1, y, bg);
    put_pixel(x + w - 2, y, bg);
    put_pixel(x + w - 1, y + 1, bg);

    put_pixel(x, y + h - 1, bg);
    put_pixel(x + 1, y + h - 1, bg);
    put_pixel(x, y + h - 2, bg);

    put_pixel(x + w - 1, y + h - 1, bg);
    put_pixel(x + w - 2, y + h - 1, bg);
    put_pixel(x + w - 1, y + h - 2, bg);
}

pub fn hit_test(x: u32, base_y: u32, w: u32, click_x: i32, click_y: i32) -> Option<EcosystemTab> {
    let rel_x = click_x as u32;
    let rel_y = click_y as u32;

    if rel_y < base_y || rel_y > base_y + TAB_HEIGHT {
        return None;
    }

    let layout = calculate_layout(w);

    for i in 0..EcosystemTab::count() {
        let (tab_x, tab_w, _) = layout.tabs[i];
        if rel_x >= x + tab_x && rel_x < x + tab_x + tab_w {
            return Some(EcosystemTab::from_u8(i as u8));
        }
    }

    None
}
