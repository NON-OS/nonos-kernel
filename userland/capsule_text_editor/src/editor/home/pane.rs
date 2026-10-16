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

//! The pane header: a title and a line saying what the lists below hold.
//!
//! It greeted a named person ("Welcome back, Mehedi") on every machine, and
//! drew a search field that took no input and a "Create New" card of
//! templates (Report, Letter, Resume, Project Plan) that did nothing. The
//! editor has no accounts, no document index and no templates; a new document
//! is File > New Tab or Ctrl+N.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::editor::widget::truncate_to_width;

use super::metrics::{lh, BODY, HEAD, PANE_PAD};
use super::metrics_pane::pane_content;

const TITLE_TEXT: &str = "Documents";
const STRAPLINE: &str = "Open a file from the store, or one this session opened.";

pub(super) fn paint_pane_head(fb: &mut PaintBuffer) {
    let ((x, w), r) = (pane_content(fb.width), roles());
    let head = truncate_to_width(fb, TITLE_TEXT, HEAD, w as i32);
    let _ = fb.text_ttf(x as i32, PANE_PAD as i32, head, r.text.argb(), HEAD);
    let sub_y = (PANE_PAD + lh(HEAD) + 4) as i32;
    let sub = truncate_to_width(fb, STRAPLINE, BODY, w as i32);
    let _ = fb.text_ttf(x as i32, sub_y, sub, r.muted.argb(), BODY);
}
