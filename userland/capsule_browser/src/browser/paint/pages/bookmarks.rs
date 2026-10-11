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
use nonos_libc::mk_time_millis;

use crate::browser::paint::glyph::Glyph;
use crate::browser::paint::pages::cells::{right_text, site_tile, trail_glyph};
use crate::browser::paint::pages::rows::{self, GAP};
use crate::browser::paint::tokens;
use crate::browser::shell::clock::ago;
use crate::browser::shell::listing::bookmark_rows;
use crate::browser::shell::site_label;
use crate::browser::shell::types::Bookmark;
use crate::browser::shell::Shell;
use crate::browser::ui::list_geom::ListGeom;
use crate::browser::ui::rect::Rect;

const NONE_YET: &str = "No bookmarks yet. The star in the address bar adds one.";

/// The Bookmarks list, newest first, each with when it was added and a
/// button that removes it.
pub fn paint(shell: &Shell, g: &ListGeom, fb: &mut PaintBuffer) {
    let list = bookmark_rows(shell);
    if list.is_empty() {
        return rows::empty(fb, g, NONE_YET);
    }
    rows::frame(fb, g, list.len());
    let now = mk_time_millis();
    for (i, &b) in list.iter().enumerate() {
        let r = g.row_rect(i);
        if rows::shown(fb, r) {
            row(fb, r, &shell.bookmarks[b], now);
        }
    }
}

fn row(fb: &mut PaintBuffer, r: Rect, b: &Bookmark, now: i64) {
    site_tile(fb, r, &site_label::site(&b.url));
    let x = trail_glyph(fb, r, Glyph::Close);
    let x = right_text(fb, r, x - GAP / 2, &ago(now, b.at_ms), tokens::MUTED);
    rows::lines(fb, r, x, &site_label::title(&b.title, &b.url), &b.url);
}
