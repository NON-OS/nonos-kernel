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

use super::{devices, state};

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 44;
const SLIDER_X: u32 = 180;
const SLIDER_W: u32 = 180;
const MUTE_X: u32 = SLIDER_X + SLIDER_W + 16;

pub fn handle_click(rel_x: u32, rel_y: u32, content_w: u32) -> bool {
    if rel_y < SECTION_Y {
        return false;
    }
    let row = (rel_y - SECTION_Y) / ROW_HEIGHT;
    match row {
        0 => handle_output_volume(rel_x),
        1 => handle_output_device(rel_x, content_w),
        2 => handle_balance(rel_x),
        3 | 4 => handle_input_volume(rel_x, rel_y),
        _ => false,
    }
}

fn handle_output_volume(rel_x: u32) -> bool {
    if rel_x >= MUTE_X && rel_x < MUTE_X + 50 {
        let current = state::get_state().output_muted;
        state::set_output_muted(!current);
        return true;
    }
    handle_slider(rel_x, state::set_output_volume)
}

fn handle_slider<F: FnOnce(u8)>(rel_x: u32, setter: F) -> bool {
    if rel_x >= SLIDER_X && rel_x < SLIDER_X + SLIDER_W {
        let pct = ((rel_x - SLIDER_X) * 100 / SLIDER_W) as u8;
        setter(pct.min(100));
        return true;
    }
    false
}

fn handle_output_device(rel_x: u32, content_w: u32) -> bool {
    if rel_x >= content_w - 220 && rel_x < content_w - 40 {
        let current = state::get_state().output_device_id;
        let count = devices::get_output_devices().len() as u8;
        state::set_output_device((current + 1) % count);
        return true;
    }
    false
}

fn handle_balance(rel_x: u32) -> bool {
    handle_slider(rel_x, state::set_balance)
}

fn handle_input_volume(rel_x: u32, rel_y: u32) -> bool {
    let input_row_y = SECTION_Y + ROW_HEIGHT * 3 + 20;
    if rel_y >= input_row_y && rel_y < input_row_y + ROW_HEIGHT {
        return handle_slider(rel_x, state::set_input_volume);
    }
    false
}
