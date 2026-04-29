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
use super::resolution;
use super::scaling;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 48;

pub fn handle_click(rel_x: u32, rel_y: u32, content_w: u32) -> bool {
    if rel_y < SECTION_Y || rel_x < content_w - 200 {
        return false;
    }
    let row = (rel_y - SECTION_Y) / ROW_HEIGHT;
    match row {
        0 => handle_resolution_click(),
        1 => handle_scaling_click(),
        2 => handle_brightness_click(rel_x, content_w),
        3 => handle_night_shift_click(),
        _ => false,
    }
}

fn handle_resolution_click() -> bool {
    let current = state::get_state().resolution_idx;
    let next = (current + 1) % resolution::resolution_count() as u8;
    state::set_resolution(next);
    true
}

fn handle_scaling_click() -> bool {
    let current = state::get_state().scale_factor;
    let idx = scaling::scale_index(current);
    let next_idx = (idx + 1) % scaling::scale_count();
    state::set_scale(scaling::scale_from_index(next_idx));
    true
}

fn handle_brightness_click(rel_x: u32, _content_w: u32) -> bool {
    let bar_x = 150;
    let bar_w = 200;
    if rel_x >= bar_x && rel_x < bar_x + bar_w {
        let pct = ((rel_x - bar_x) * 100 / bar_w) as u8;
        state::set_brightness(pct.min(100));
        return true;
    }
    false
}

fn handle_night_shift_click() -> bool {
    let current = state::get_state().night_shift_enabled;
    state::set_night_shift(!current);
    true
}
