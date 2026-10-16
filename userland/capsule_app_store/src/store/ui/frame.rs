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

//! One frame: ground, head, tabs, list, detail, status.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Rect, Scrollbar};

use crate::store::state::State;

use super::metrics::{CARD_GAP, CARD_H, DETAIL_W, PAD_X, SCROLL_GAP, SCROLL_W, STATUS_H};
use super::{chrome, detail, geometry, rows, status};

pub fn frame(state: &mut State, fb: &mut PaintBuffer) {
    fb.clear(roles().bg.argb());
    state.fb_w = fb.width;
    state.fb_h = fb.height;
    chrome::head(fb, state);
    chrome::tabs(fb, state);
    let top = geometry::list_top();

    let bottom = fb.height.saturating_sub(STATUS_H + PAD_X);
    let pane_h = bottom.saturating_sub(top);
    state.rows = (pane_h / (CARD_H + CARD_GAP)).max(1) as usize;
    /* Clamped here because this is where the row count is known. */
    state.clamp_scroll();

    let list_w = geometry::list_w(fb.width);
    rows::paint(state, fb, PAD_X, top, list_w, state.rows);
    let total = state.visible().len() as u32;
    let track_h = state.rows as u32 * (CARD_H + CARD_GAP) - CARD_GAP;
    let track = Rect { x: PAD_X + list_w + SCROLL_GAP, y: top, w: SCROLL_W, h: track_h };
    Scrollbar::new(state.scroll as u32, total, state.rows as u32).draw(fb, track);

    let detail_x = PAD_X + list_w + PAD_X;
    detail::paint(state, fb, detail_x, top, DETAIL_W, pane_h);
    status::paint(fb, state);
}
