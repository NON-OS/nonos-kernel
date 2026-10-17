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

//! The head band, its search field and the source tabs.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{text, Field, Rect, State as Look};

use crate::store::search::Search;
use crate::store::state::{State, TABS};

use super::bytes::as_str;
use super::counter::listed;
use super::hover_look::pointed;
use super::metrics::{BODY_PX, HEAD_H, PAD_TOP, PAD_X, SEARCH_H, SEARCH_W, TITLE_PX};
use super::tab_strip;
use super::target::Target;

pub fn head(fb: &mut PaintBuffer, state: &State) {
    let r = roles();
    let top = text::centre_top(PAD_TOP, HEAD_H, TITLE_PX);
    text::left(fb, PAD_X, top, "Marketplace", r.text, TITLE_PX);
    let right = state.fb_w.saturating_sub(PAD_X);
    let field = search(fb, &state.search, right);
    let meta_top = text::centre_top(PAD_TOP, HEAD_H, BODY_PX);
    let count = state.visible().len();
    let at = right.saturating_sub(field + if field == 0 { 0 } else { PAD_X });
    text::right(fb, at, meta_top, as_str(&listed(count)), r.muted, BODY_PX);
}

/// Paints the field while it is open or holds a word, and reports how much
/// width it took, so the head can put its count to the left of it rather
/// than underneath.
fn search(fb: &mut PaintBuffer, search: &Search, right: u32) -> u32 {
    if !search.active && search.text().is_empty() {
        return 0;
    }
    let query = as_str(search.text());
    let y = PAD_TOP + (HEAD_H - SEARCH_H) / 2;
    let at = Rect { x: right.saturating_sub(SEARCH_W), y, w: SEARCH_W, h: SEARCH_H };
    Field::new(query)
        .placeholder("type to search")
        .caret(search.active.then_some(query.len()))
        .state(Look { focused: search.active, ..Look::default() })
        .draw(fb, at);
    SEARCH_W
}

/// The source tabs, one strip across the set, with the tab under the pointer
/// washed.
pub fn tabs(fb: &mut PaintBuffer, state: &State) {
    let hovered = (0..TABS.len()).find(|&i| pointed(state, |t| t == Target::Tab(i)).hovered);
    tab_strip::draw(fb, state.fb_w, Some(state.tab), hovered);
}
