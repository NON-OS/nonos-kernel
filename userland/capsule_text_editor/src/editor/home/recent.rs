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

//! The document column. Rows come from the VFS listing (or the session's
//! most-recently-opened list) and open on a click; the subtitle is the store
//! path, the only thing about a document the editor actually knows.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::mix;
use nonos_toolkit::theme::roles;

use crate::editor::widget::{paint_docrow, DocRowStyle};

use super::super::app::Editor;
use super::docs::{doc_list, empty_line, section_title};
use super::metrics::{lh, BODY, DOC_ICON, SUBHEAD};
use super::metrics_pane::{cols_y, doc_row_h, docs_list_rect, docs_rect};
use super::state::HomeState;

/// How far a sunk line moves towards the ground, out of 255: nine twentieths.
const SINK: u8 = 115;

/// Sink an ink part-way back into the page: the empty-list line, and "View all"
/// while it would lead to the list already shown.
fn dim(ink: u32) -> u32 {
    mix(ink, roles().bg.argb(), SINK)
}

pub(super) fn paint_recent(ed: &Editor, fb: &mut PaintBuffer, nav: usize) {
    let (hx, _, hw) = docs_rect(fb.width);
    let (head_y, r) = (cols_y(fb.width), roles());
    let _ = fb.text_ttf(hx as i32, head_y as i32, section_title(nav), r.text.argb(), SUBHEAD);
    paint_view_all(fb, hx, head_y, hw, nav != 0);
    let list = doc_list(ed, nav);
    let (x, y, w, total) = docs_list_rect(fb.width, fb.height, list.len());
    if total == 0 {
        let _ = fb.text_ttf(x as i32, y as i32, empty_line(nav), dim(r.quiet.argb()), BODY);
        return;
    }
    let st = DocRowStyle {
        icon_bg: r.raised.argb(),
        icon_mark: r.muted.argb(),
        icon_radius: 6,
        title: r.text.argb(),
        subtitle: r.quiet.argb(),
        gap: 14,
    };
    let rh = doc_row_h();
    for (i, doc) in list.iter().take((total / rh) as usize).enumerate() {
        let rect = (x, y + i as u32 * rh, w, rh);
        paint_docrow(fb, rect, DOC_ICON, (&doc.name, &doc.path), (BODY, BODY), &st);
    }
}

fn paint_view_all(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, live: bool) {
    let label = "View all";
    let lw = fb.measure_ttf(label, BODY).max(0) as u32;
    let lx = x + w.saturating_sub(lw);
    let ly = y + lh(SUBHEAD).saturating_sub(lh(BODY)) / 2;
    let accent = roles().accent.argb();
    let color = if live { accent } else { dim(accent) };
    let _ = fb.text_ttf(lx as i32, ly as i32, label, color, BODY);
    let rect = (lx, ly, if live { lw } else { 0 }, lh(BODY));
    HomeState::note_view_all(rect);
}
