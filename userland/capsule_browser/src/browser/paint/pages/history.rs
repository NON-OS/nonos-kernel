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

use crate::browser::paint::glyph::Glyph;
use crate::browser::paint::pages::cells::{right_glyph, right_text, site_tile};
use crate::browser::paint::pages::rows::{self, GAP, PAD};
use crate::browser::paint::tokens;
use crate::browser::paint::toolbar::route_look;
use crate::browser::shell::clock::hhmm;
use crate::browser::shell::listing::history_rows;
use crate::browser::shell::route::Route;
use crate::browser::shell::site_label;
use crate::browser::shell::types::Visit;
use crate::browser::shell::Shell;
use crate::browser::ui::list_geom::ListGeom;
use crate::browser::ui::rect::Rect;

const ROUTE_GAP: i32 = 6;
const NONE_YET: &str = "No pages visited yet this session.";
const NONE_HERE: &str = "No pages visited on this route.";

/// The History list, newest first, under the route filter in force.
pub fn paint(shell: &Shell, g: &ListGeom, fb: &mut PaintBuffer) {
    let list = history_rows(shell);
    if list.is_empty() {
        let msg = if shell.visits.is_empty() { NONE_YET } else { NONE_HERE };
        return rows::empty(fb, g, msg);
    }
    rows::frame(fb, g, list.len());
    for (i, &v) in list.iter().enumerate() {
        let r = g.row_rect(i);
        if rows::shown(fb, r) {
            row(fb, r, &shell.visits[v]);
        }
    }
}

/* A visit: its site tile, title over host, the time, and the route it came
 * by, an anonymising one in its shield. */
fn row(fb: &mut PaintBuffer, r: Rect, v: &Visit) {
    site_tile(fb, r, &site_label::site(&v.url));
    let (name, _, ink) = route_look(v.route);
    let glyph = match v.route {
        Route::Direct => Glyph::Globe,
        Route::Socks | Route::Mixnet | Route::Anyone => Glyph::Shield,
    };
    let x = right_text(fb, r, r.right() - PAD, name, ink);
    let x = right_glyph(fb, r, x - ROUTE_GAP, glyph, ink);
    let x = right_text(fb, r, x - GAP, &hhmm(v.at_ms), tokens::MUTED);
    rows::lines(fb, r, x, &site_label::title(&v.title, &v.url), &v.host);
}
