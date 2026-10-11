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

use super::{article, flow, panel};
use crate::browser::paint::tokens;
use crate::browser::shell::Shell;
use crate::browser::ui::list_geom::max_scroll;
use crate::browser::ui::{reader_column, reader_geom};

/// The reader page, into a buffer the size of the content area: the themed
/// ground, the article column at its scroll, then the settings card.
pub fn paint(shell: &Shell, fb: &mut PaintBuffer) {
    let [bg, fg, dim] = tokens::READER_THEMES[(shell.reader.theme as usize).min(2)];
    let (w, h) = (fb.width as i32, fb.height as i32);
    fb.fill_rect(0, 0, fb.width, fb.height, bg);
    if let Some(a) = shell.article.as_ref() {
        let (x, cw) = reader_column::column(w, shell.reader.width);
        let f = flow::flow(a, &shell.reader, cw);
        let scroll = shell.page_scroll.clamp(0, max_scroll(f.height, h));
        article::paint(fb, a, &f, x, scroll, fg, dim);
    }
    panel::paint(&shell.reader, &reader_geom::panel(w), fb);
}

/// How tall the article the window holds stands in a `w` wide content area.
pub fn height(shell: &Shell, w: i32) -> i32 {
    let Some(a) = shell.article.as_ref() else { return 0 };
    let (_, cw) = reader_column::column(w, shell.reader.width);
    flow::flow(a, &shell.reader, cw).height
}
