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

use super::glass_panel::{draw_glass_panel, GlassVariant};
use crate::graphics::design_system::{borders, colors, spacing};
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, rounded_rect_blend};

pub const DROPDOWN_HEIGHT: u32 = 36;
pub const DROPDOWN_ITEM_HEIGHT: u32 = 32;
pub const DROPDOWN_PADDING: u32 = 12;

pub struct DropdownState {
    pub open: bool,
    pub selected: usize,
    pub hovered: i32,
}

impl Default for DropdownState {
    fn default() -> Self {
        Self { open: false, selected: 0, hovered: -1 }
    }
}

pub fn draw_dropdown(x: u32, y: u32, w: u32, label: &[u8], state: &DropdownState) {
    let bg = if state.open { colors::GLASS_BG_ACTIVE } else { colors::GLASS_BG };
    rounded_rect_blend(x, y, w, DROPDOWN_HEIGHT, borders::RADIUS_MD, bg);
    draw_text(x + DROPDOWN_PADDING, y + 10, label, colors::TEXT_PRIMARY);
    draw_chevron(x + w - 24, y + 14, state.open);
}

pub fn draw_dropdown_menu(x: u32, y: u32, w: u32, items: &[&[u8]], state: &DropdownState) {
    if !state.open {
        return;
    }
    let menu_h = items.len() as u32 * DROPDOWN_ITEM_HEIGHT + spacing::SPACE_2 * 2;
    draw_glass_panel(x, y, w, menu_h, GlassVariant::Default, borders::RADIUS_MD);
    for (i, item) in items.iter().enumerate() {
        let item_y = y + spacing::SPACE_2 + i as u32 * DROPDOWN_ITEM_HEIGHT;
        let is_selected = i == state.selected;
        let is_hovered = state.hovered == i as i32;
        if is_selected || is_hovered {
            let item_bg = if is_selected { colors::ACCENT } else { colors::GLASS_BG_HOVER };
            fill_rect(x + 4, item_y, w - 8, DROPDOWN_ITEM_HEIGHT, item_bg);
        }
        let text_color = if is_selected { colors::TEXT_INVERSE } else { colors::TEXT_PRIMARY };
        draw_text(x + DROPDOWN_PADDING, item_y + 8, item, text_color);
    }
}

fn draw_chevron(x: u32, y: u32, open: bool) {
    let color = colors::TEXT_SECONDARY;
    if open {
        for i in 0..4u32 {
            fill_rect(x + i, y + 4 - i, 1, 1, color);
            fill_rect(x + 7 - i, y + 4 - i, 1, 1, color);
        }
    } else {
        for i in 0..4u32 {
            fill_rect(x + i, y + i, 1, 1, color);
            fill_rect(x + 7 - i, y + i, 1, 1, color);
        }
    }
}

pub fn dropdown_hit_test(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    click_x >= x as i32
        && click_x < (x + w) as i32
        && click_y >= y as i32
        && click_y < (y + DROPDOWN_HEIGHT) as i32
}

pub fn dropdown_item_hit(y: u32, items_count: usize, click_y: i32) -> i32 {
    let menu_y = y as i32 + spacing::SPACE_2 as i32;
    let rel_y = click_y - menu_y;
    if rel_y < 0 {
        return -1;
    }
    let idx = rel_y / DROPDOWN_ITEM_HEIGHT as i32;
    if idx < items_count as i32 {
        idx
    } else {
        -1
    }
}
