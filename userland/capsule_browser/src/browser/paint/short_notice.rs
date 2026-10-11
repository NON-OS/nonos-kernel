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

//! The short .anyone name notice: a band under the toolbar, across the top of
//! the page, while the page shown was reached by a short name. It is drawn
//! after every page paint, so a scroll or a partial repaint never leaves the
//! page without it.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::paint::measure_ttf;

use crate::browser::paint::chrome::constants::{BORDER, WARN};
use crate::browser::short_name::{notice_for, wrap};
use crate::browser::state::{State, View};

const BAND_BG: u32 = 0xFF2A_2418;
const PX: f32 = 13.0;
const LINE_H: u32 = 18;
const PAD: u32 = 10;
/// At most this many lines: a window too narrow for the whole notice keeps
/// the page in view and the first lines say what matters.
const LINES_MAX: usize = 3;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    if state.view != View::Page {
        return;
    }
    let Some(notice) = state.ui.history.current().and_then(notice_for) else {
        return;
    };
    let room = fb.width.saturating_sub(PAD * 2) as i32;
    let lines = wrap(notice, room, |t| measure_ttf(t, PX));
    let shown = lines.len().min(LINES_MAX) as u32;
    let h = shown * LINE_H + PAD;
    fb.fill_rect(0, 0, fb.width, h, BAND_BG);
    fb.fill_rect(0, h, fb.width, 1, BORDER);
    for (i, line) in lines.iter().take(LINES_MAX).enumerate() {
        let y = PAD / 2 + i as u32 * LINE_H;
        fb.text_ttf(PAD as i32, y as i32, line, WARN, PX);
    }
}
