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

use super::state;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 40;

pub fn handle_click(_rel_x: u32, rel_y: u32, _content_w: u32) -> bool {
    if rel_y < SECTION_Y {
        return false;
    }
    let row = (rel_y - SECTION_Y) / ROW_HEIGHT;
    match row {
        0 => cycle_font_size(),
        1 => cycle_cursor_size(),
        2 => toggle_bold(),
        3 => toggle_contrast(),
        4 => toggle_motion(),
        5 => toggle_transparency(),
        6 => toggle_invert(),
        7 => toggle_keyboard_nav(),
        8 => toggle_zoom(),
        _ => false,
    }
}

fn cycle_font_size() -> bool {
    let current = state::get_state().font_size_idx;
    state::set_font_size((current + 1) % 4);
    true
}

fn cycle_cursor_size() -> bool {
    let current = state::get_state().cursor_size_idx;
    state::set_cursor_size((current + 1) % 4);
    true
}

fn toggle_bold() -> bool {
    let v = state::get_state().bold_text;
    state::set_bold_text(!v);
    true
}

fn toggle_contrast() -> bool {
    let v = state::get_state().high_contrast;
    state::set_high_contrast(!v);
    true
}

fn toggle_motion() -> bool {
    let v = state::get_state().reduce_motion;
    state::set_reduce_motion(!v);
    true
}

fn toggle_transparency() -> bool {
    let v = state::get_state().reduce_transparency;
    state::set_reduce_transparency(!v);
    true
}

fn toggle_invert() -> bool {
    let v = state::get_state().invert_colors;
    state::set_invert_colors(!v);
    true
}

fn toggle_keyboard_nav() -> bool {
    let v = state::get_state().keyboard_navigation;
    state::set_keyboard_nav(!v);
    true
}

fn toggle_zoom() -> bool {
    let v = state::get_state().zoom_enabled;
    state::set_zoom_enabled(!v);
    true
}
