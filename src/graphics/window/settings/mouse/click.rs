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
const ROW_HEIGHT: u32 = 44;
const SLIDER_X: u32 = 200;
const SLIDER_W: u32 = 160;

pub fn handle_click(rel_x: u32, rel_y: u32, _content_w: u32) -> bool {
    if rel_y < SECTION_Y {
        return false;
    }
    let row = (rel_y - SECTION_Y) / ROW_HEIGHT;
    match row {
        0 => handle_slider(rel_x, state::set_tracking_speed),
        1 => handle_slider(rel_x, state::set_scroll_speed),
        2 => handle_slider(rel_x, state::set_double_click_speed),
        3 => handle_natural_scroll(),
        4 => handle_acceleration(),
        _ => false,
    }
}

fn handle_slider<F: FnOnce(u8)>(rel_x: u32, setter: F) -> bool {
    if rel_x >= SLIDER_X && rel_x < SLIDER_X + SLIDER_W {
        let pct = ((rel_x - SLIDER_X) * 100 / SLIDER_W) as u8;
        setter(pct.min(100));
        return true;
    }
    false
}

fn handle_natural_scroll() -> bool {
    let current = state::get_state().natural_scroll;
    state::set_natural_scroll(!current);
    true
}

fn handle_acceleration() -> bool {
    let current = state::get_state().pointer_acceleration;
    state::set_pointer_acceleration(!current);
    true
}
