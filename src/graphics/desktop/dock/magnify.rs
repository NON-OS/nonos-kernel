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

use super::state::{get_hover_position, is_magnification_enabled, set_hover_index, set_hover_position};
use crate::graphics::desktop::constants::DOCK_ICON_COUNT;

const BASE_SIZE: u32 = 44;
const MAX_SIZE: u32 = 64;
const FALLOFF_DISTANCE: i32 = 100;
const ICON_SPACING: u32 = 58;

pub(super) fn update_hover_position(mx: i32, my: i32, dock_x: u32, dock_y: u32, dock_h: u32) {
    if !is_magnification_enabled() { return; }
    let in_y = my >= dock_y as i32 && my < (dock_y + dock_h) as i32;
    let in_x = mx >= dock_x as i32 && mx < (dock_x + DOCK_ICON_COUNT as u32 * ICON_SPACING + 28) as i32;
    if !in_y || !in_x {
        super::state::clear_hover();
        return;
    }
    set_hover_position(mx, my);
    let rel_x = mx - dock_x as i32;
    let idx = ((rel_x - 14) / ICON_SPACING as i32).max(0) as u8;
    if (idx as usize) < DOCK_ICON_COUNT { set_hover_index(Some(idx)); }
    else { set_hover_index(None); }
}

pub(super) fn get_magnified_size(icon_index: u32, dock_x: u32) -> u32 {
    if !is_magnification_enabled() { return BASE_SIZE; }
    let (hover_x, _) = get_hover_position();
    if hover_x < 0 { return BASE_SIZE; }
    let center = dock_x as i32 + 14 + (icon_index as i32 * ICON_SPACING as i32) + (BASE_SIZE as i32 / 2);
    let dist = (hover_x - center).abs();
    if dist >= FALLOFF_DISTANCE { return BASE_SIZE; }
    let factor = 1.0 - (dist as f32 / FALLOFF_DISTANCE as f32);
    BASE_SIZE + ((MAX_SIZE - BASE_SIZE) as f32 * factor * factor) as u32
}

pub(super) fn get_icon_y_offset(magnified_size: u32) -> i32 {
    -((magnified_size as i32 - BASE_SIZE as i32) / 2)
}
