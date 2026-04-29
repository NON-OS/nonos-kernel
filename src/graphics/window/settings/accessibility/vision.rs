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

pub fn get_effective_font_scale() -> u32 {
    let idx = state::get_state().font_size_idx;
    match idx {
        0 => 1,
        1 => 1,
        2 => 2,
        3 => 2,
        _ => 1,
    }
}

pub fn get_cursor_scale() -> u32 {
    let idx = state::get_state().cursor_size_idx;
    match idx {
        0 | 1 => 1,
        2 => 2,
        3 => 3,
        _ => 1,
    }
}

pub fn should_reduce_motion() -> bool {
    state::get_state().reduce_motion
}

pub fn should_reduce_transparency() -> bool {
    state::get_state().reduce_transparency
}

pub fn is_high_contrast() -> bool {
    state::get_state().high_contrast
}

pub fn is_inverted() -> bool {
    state::get_state().invert_colors
}

pub fn font_size_label(idx: u8) -> &'static str {
    state::FONT_SIZES.get(idx as usize).map(|(s, _)| *s).unwrap_or("Default")
}

pub fn cursor_size_label(idx: u8) -> &'static str {
    state::CURSOR_SIZES.get(idx as usize).map(|(s, _)| *s).unwrap_or("Normal")
}
