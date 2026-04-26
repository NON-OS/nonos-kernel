// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::font::draw_string;
use crate::display::gop::fill_rect;
use crate::menu::brand;
use crate::menu::types::MenuState;
use super::layout::ENTRY_H;

pub fn draw_entries(state: &MenuState, x: u32, y: u32, w: u32) {
    for (i, action) in state.entries.iter().enumerate() {
        let ey = y + (i as u32 * ENTRY_H);
        let sel = i == state.selected;
        let (bg, fg) = if sel { (brand::BG_SECONDARY, brand::TEXT_PRIMARY) } else { (brand::BG_CARD, brand::TEXT_MUTED) };
        fill_rect(x, ey, w, ENTRY_H - 4, bg);
        if sel { fill_rect(x, ey, 4, ENTRY_H - 4, brand::ACCENT_PRIMARY); }
        draw_string(x + 20, ey + 12, action.label().as_bytes(), fg);
    }
}
