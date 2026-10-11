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

use nonos_app_skeleton::{measure_ttf, PaintBuffer};

use crate::browser::omnibox::geometry::{search_rect, TEXT_PX};
use crate::browser::omnibox::{text_offset, Focus};
use crate::browser::paint::home_page::constants;
use crate::browser::paint::{field_text, FieldInk};
use crate::browser::state::State;

/* The home page search bar. It is the address bar's twin: same text, same
 * caret and selection, drawn wider in the middle of the page. */
pub fn search_bar(state: &State, fb: &mut PaintBuffer) {
    let focused = state.ui.kbd == Focus::Omnibox;
    let edge = if focused { constants::ACCENT } else { constants::BORDER };
    let r = search_rect(fb.width);
    fb.fill_rect(r.x, r.y, r.w, r.h, edge);
    fb.fill_rect(r.x + 2, r.y + 2, r.w - 4, r.h - 4, constants::PILL_BG);
    globe(fb, r.x + 16, r.y + 15);
    let ed = &state.ui.omnibox;
    let w = r.w - 56;
    let caret_px = measure_ttf(&ed.text[..ed.caret], TEXT_PX);
    let off = text_offset(caret_px, measure_ttf(&ed.text, TEXT_PX), w as i32, 0);
    let boxed = (r.x + 40, r.y + 2, w, r.h - 4);
    let ink = FieldInk { text: constants::FG, hint: constants::DIM, select: constants::SELECTION };
    field_text(fb, boxed, ed, (focused, off), "Search or enter a URL", ink);
}

fn globe(fb: &mut PaintBuffer, x: u32, y: u32) {
    fb.fill_rect(x, y, 16, 16, constants::DIM);
    fb.fill_rect(x, y, 2, 2, constants::PILL_BG);
    fb.fill_rect(x + 14, y, 2, 2, constants::PILL_BG);
    fb.fill_rect(x, y + 14, 2, 2, constants::PILL_BG);
    fb.fill_rect(x + 14, y + 14, 2, 2, constants::PILL_BG);
    fb.fill_rect(x + 7, y, 2, 16, constants::PILL_BG);
    fb.fill_rect(x, y + 7, 16, 2, constants::PILL_BG);
}
