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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::font::ttf::line_height;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Card, Rect, Scrollbar};

use super::history_row;
use crate::calc::state::State;
use crate::calc::ui::history_geom::{capacity, entry_at, pane, PAD};
use crate::calc::ui::metrics::PX_BODY;

const EMPTY: &str = "No calculations yet";

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let (x, y, w, h) = pane(fb.width as i32, fb.height as i32);
    if w <= PAD * 2 || h <= 0 || x < 0 || y < 0 {
        return;
    }
    Card::new().draw(fb, Rect { x: x as u32, y: y as u32, w: w as u32, h: h as u32 });
    if state.history.is_empty() {
        let lh = line_height(PX_BODY).max(1);
        let tx = x + (w - fb.measure_ttf(EMPTY, PX_BODY)) / 2;
        fb.text_ttf(tx, y + (h - lh) / 2, EMPTY, roles().quiet.argb(), PX_BODY);
        return;
    }
    let rows = capacity(fb.height as i32);
    for i in 0..rows {
        if let Some(entry) = state.history.get(entry_at(state.history_scroll, i)) {
            history_row::paint(state, fb, i, entry);
        }
    }
    thumb(state, fb, (x, y, w, h), rows);
}

/// A slim bar on the pane's right edge when the ring holds more than the page
/// shows: where the page is among all of them, and that there is more.
fn thumb(state: &State, fb: &mut PaintBuffer, pane: (i32, i32, i32, i32), rows: usize) {
    let len = state.history.len();
    if rows == 0 || len <= rows {
        return;
    }
    let (x, y, w, h) = pane;
    let track = Rect { x: (x + w - 6) as u32, y: (y + PAD) as u32, w: 3, h: (h - PAD * 2) as u32 };
    Scrollbar::new(state.history_scroll as u32, len as u32, rows as u32).draw(fb, track);
}
