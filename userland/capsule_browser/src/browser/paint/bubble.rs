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

use alloc::string::ToString;

use nonos_app_skeleton::PaintBuffer;

use crate::browser::omnibox::geometry::BUBBLE_BAND;
use crate::browser::paint::tokens::palette;
use crate::browser::url;

const PX: f32 = 13.0;

/* The address of the link under the pointer, in a bubble at the page's
 * bottom-left corner, clipped to half the window width; with no link
 * under it, a notice for the reader if one is up, which may take the
 * window's width: a page's alert is read whole where it fits. */
pub(super) fn paint(state: &crate::browser::state::State, fb: &mut PaintBuffer) {
    let (text, room) = match (state.ui.hover_href.as_deref(), state.ui.notice.as_ref()) {
        (Some(href), _) => match state.base.as_ref() {
            Some(b) => (url::join(b, href), fb.width / 2),
            None => (href.to_string(), fb.width / 2),
        },
        (None, Some((line, _))) => (line.clone(), fb.width.saturating_sub(4)),
        (None, None) => return,
    };
    let h = BUBBLE_BAND - 4;
    let w = (fb.measure_ttf(&text, PX).max(0) as u32 + 16).min(room);
    let y = fb.height.saturating_sub(BUBBLE_BAND);
    let p = palette();
    fb.fill_rect(2, y, w, h, p.edge);
    fb.fill_rect(3, y + 1, w.saturating_sub(2), h - 2, p.surface);
    let mut sub = fb.sub(10, y + 2, w.saturating_sub(16), h - 4);
    sub.text_ttf(0, 0, &text, p.ink, PX);
}
