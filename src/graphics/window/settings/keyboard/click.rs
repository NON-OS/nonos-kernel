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
const BAR_X: u32 = 180;
const BAR_W: u32 = 160;

pub fn handle_click(rel_x: u32, rel_y: u32, _content_w: u32) -> bool {
    if rel_y < SECTION_Y {
        return false;
    }
    let row = (rel_y - SECTION_Y) / ROW_HEIGHT;
    match row {
        0 => handle_layout_click(),
        1 => handle_slider_click(rel_x, |v| state::set_repeat_rate(v)),
        2 => handle_slider_click(rel_x, |v| state::set_repeat_delay(v)),
        3 => handle_caps_led_click(),
        4 => handle_fn_key_click(),
        _ => false,
    }
}

fn handle_layout_click() -> bool {
    let current = state::get_state().layout_index;
    let next = (current + 1) % state::LAYOUTS.len() as u8;
    state::set_layout(next);
    true
}

fn handle_slider_click<F: FnOnce(u8)>(rel_x: u32, setter: F) -> bool {
    if rel_x >= BAR_X && rel_x < BAR_X + BAR_W {
        let pct = ((rel_x - BAR_X) * 100 / BAR_W) as u8;
        setter(pct.min(100));
        return true;
    }
    false
}

fn handle_caps_led_click() -> bool {
    let current = state::get_state().caps_lock_led;
    state::set_caps_lock_led(!current);
    true
}

fn handle_fn_key_click() -> bool {
    let current = state::get_state().fn_key_standard;
    state::set_fn_key_standard(!current);
    true
}
