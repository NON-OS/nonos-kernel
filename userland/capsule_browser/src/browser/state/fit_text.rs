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

use nonos_app_skeleton::measure_ttf;

use super::State;
use crate::browser::omnibox::geometry::{pill_text_w, TEXT_PX};
use crate::browser::omnibox::text_offset;

impl State {
    /* Scroll the address text so the caret stays inside the pill. */
    pub fn fit_text(&mut self) {
        let ed = &self.ui.omnibox;
        let caret_px = measure_ttf(&ed.text[..ed.caret], TEXT_PX);
        let text_px = measure_ttf(&ed.text, TEXT_PX);
        let w = pill_text_w(self.layout.toolbar.w as u32, self.ui.truncated) as i32;
        self.ui.text_off = text_offset(caret_px, text_px, w, self.ui.text_off);
    }
}
