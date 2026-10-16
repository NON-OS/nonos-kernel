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
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::Scrollbar;

use crate::pm::state::notes::empty_table;
use crate::pm::state::State;

use super::chrome::Rect;
use super::metrics::{BODY_PX, ROW_H, SCROLL_PAD, SCROLL_W, TBL_HEAD_H, TBL_RADIUS};
use super::table_geom::{self, Col};
use super::{table_head, table_row, text};

// The card border is stroked last so neither the header band nor a selected
// row's wash paints over it. Every offset inside the card comes from table_geom,
// which is also what the hit test reads, so a click cannot land on a row or a
// column other than the one drawn under it.
pub fn paint(state: &State, fb: &mut PaintBuffer, r: &Rect, cols: &[Col]) {
    let c = roles();
    fb.fill_round(r.x, r.y, r.w, r.h, TBL_RADIUS, c.inset.argb());
    table_head::paint(fb, r, cols, state.sort);
    let rows = state.filtered();
    /*
     * Nothing to draw is never a silent blank card: the table says whether it
     * is still being read, could not be read, or is filtered to nothing.
     */
    if let Some(note) = empty_table(state.rows.len(), rows.len(), state.status) {
        let top = text::centred_top(r.y + TBL_HEAD_H, r.h.saturating_sub(TBL_HEAD_H), BODY_PX);
        let cut = text::fit(fb, note, BODY_PX, r.w.saturating_sub(SCROLL_PAD * 2));
        let x = r.x + r.w.saturating_sub(text::width(fb, cut, BODY_PX)) / 2;
        text::left(fb, x, top, cut, c.muted, BODY_PX);
    }
    let visible = table_geom::visible_rows(r.h);
    for slot in 0..visible {
        match rows.get(state.scroll + slot) {
            Some(row) if table_geom::row_y(slot) + ROW_H <= r.h => {
                table_row::paint(state, fb, r, cols, row, slot)
            }
            _ => break,
        }
    }
    scrollbar(fb, r, state.scroll, rows.len(), visible);
    fb.stroke_round(r.x, r.y, r.w, r.h, TBL_RADIUS, 1, c.border.argb());
}

// Drawn only when the list is taller than the card: the thumb's height is the
// visible share of the whole list and its travel is the real scroll offset, so
// the bar reports the position rather than decorating the edge. The toolkit
// bar, in rows, draws nothing while the list fits.
fn scrollbar(fb: &mut PaintBuffer, r: &Rect, scroll: usize, total: usize, visible: usize) {
    if r.h <= TBL_HEAD_H {
        return;
    }
    let x = r.x + r.w.saturating_sub(SCROLL_PAD + SCROLL_W);
    let track = Rect { x, y: r.y + TBL_HEAD_H, w: SCROLL_W, h: r.h - TBL_HEAD_H };
    Scrollbar::new(scroll as u32, total as u32, visible as u32).draw(fb, track);
}
