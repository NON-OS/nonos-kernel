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

use super::tabs_state::{
    active_tab, get_tab_name, is_tab_modified, tab_count, tabs_enabled, MAX_TABS,
};
use crate::graphics::font::draw_char;
use crate::display::framebuffer::{COLOR_ACCENT};
use crate::graphics::framebuffer::{fill_rect};

pub(super) const TAB_BAR_HEIGHT: u32 = 28;
const TAB_WIDTH: u32 = 120;
const BG: u32 = 0xFF1E1E2E;
const TAB_BG: u32 = 0xFF2D2D3D;
const TAB_ACTIVE: u32 = 0xFF0D1117;
const TEXT: u32 = 0xFFCDD6F4;
const MODIFIED: u32 = 0xFFD29922;

pub(super) fn draw_tabs(x: u32, y: u32, w: u32) {
    if !tabs_enabled() {
        return;
    }
    fill_rect(x, y, w, TAB_BAR_HEIGHT, BG);
    let count = tab_count();
    let active = active_tab();
    for i in 0..count.min(MAX_TABS) {
        let tx = x + (i as u32) * TAB_WIDTH;
        let bg = if i == active { TAB_ACTIVE } else { TAB_BG };
        fill_rect(tx, y, TAB_WIDTH - 2, TAB_BAR_HEIGHT - 2, bg);
        let name = get_tab_name(i);
        let display_name = extract_filename(name);
        let max_chars = ((TAB_WIDTH - 24) / 8) as usize;
        for (j, &ch) in display_name.iter().take(max_chars).enumerate() {
            draw_char(tx + 8 + (j as u32) * 8, y + 6, ch, TEXT);
        }
        if is_tab_modified(i) {
            draw_char(tx + TAB_WIDTH - 18, y + 6, b'*', MODIFIED);
        }
        draw_char(tx + TAB_WIDTH - 10, y + 6, b'x', 0xFF6C6C7C);
    }
    if count < MAX_TABS {
        let tx = x + (count as u32) * TAB_WIDTH;
        fill_rect(tx, y, 24, TAB_BAR_HEIGHT - 2, TAB_BG);
        draw_char(tx + 8, y + 6, b'+', COLOR_ACCENT);
    }
}

fn extract_filename(path: &[u8]) -> &[u8] {
    for i in (0..path.len()).rev() {
        if path[i] == b'/' {
            return &path[i + 1..];
        }
    }
    if path.is_empty() {
        b"untitled"
    } else {
        path
    }
}

pub(super) fn handle_tab_click(x: u32, _y: u32, click_x: u32) -> bool {
    if !tabs_enabled() {
        return false;
    }
    let count = tab_count();
    let rel_x = click_x.saturating_sub(x);
    let idx = (rel_x / TAB_WIDTH) as usize;
    if idx < count {
        let within_tab = rel_x % TAB_WIDTH;
        if within_tab > TAB_WIDTH - 14 {
            super::tabs_state::close_tab(idx);
        } else {
            super::tabs_state::switch_tab(idx);
        }
        return true;
    } else if idx == count && count < MAX_TABS {
        super::tabs_state::new_tab();
        return true;
    }
    false
}
