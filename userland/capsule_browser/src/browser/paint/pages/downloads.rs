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

use alloc::format;
use alloc::string::String;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};

use crate::browser::paint::glyph::Glyph;
use crate::browser::paint::pages::cells::{right_glyph, right_text, tile, trail_glyph};
use crate::browser::paint::pages::rows::{self, GAP, PX, WIDE_TILE};
use crate::browser::paint::start::tile_color;
use crate::browser::paint::tokens::palette;
use crate::browser::shell::downloads::human_bytes;
use crate::browser::shell::listing::download_rows;
use crate::browser::shell::types::{DlState, Download};
use crate::browser::shell::visits::host_of;
use crate::browser::shell::Shell;
use crate::browser::ui::fit;
use crate::browser::ui::list_geom::ListGeom;
use crate::browser::ui::rect::Rect;

const STATE_GAP: i32 = 8;
const SAVING: &str = "Saving\u{2026}";
const SAVED: &str = "Saved to /home/Downloads";
const NONE_YET: &str = "No downloads yet. Files the page cannot show are saved here.";
const NONE_HERE: &str = "No downloads match this filter.";

/// The Downloads list, newest first, under the state filter in force.
pub fn paint(shell: &Shell, g: &ListGeom, fb: &mut PaintBuffer) {
    let list = download_rows(shell);
    if list.is_empty() {
        let msg = if shell.downloads.is_empty() { NONE_YET } else { NONE_HERE };
        return rows::empty(fb, g, msg);
    }
    rows::frame(fb, g, list.len());
    for (i, &d) in list.iter().enumerate() {
        let r = g.row_rect(i);
        if rows::shown(fb, r) {
            row(fb, r, &shell.downloads[d]);
        }
    }
}

/* A download: its extension tile, name over host and size, where it went
 * or why not, and the button that drops the record. */
fn row(fb: &mut PaintBuffer, r: Rect, d: &Download) {
    let ext = ext_of(&d.name);
    tile(fb, r, &ext, tile_color(&ext), WIDE_TILE);
    let x = trail_glyph(fb, r, Glyph::Close) - GAP / 2;
    let x = match &d.state {
        DlState::Saving => right_text(fb, r, x, SAVING, palette().accent),
        DlState::Saved => {
            let x = right_text(fb, r, x, SAVED, palette().muted);
            right_glyph(fb, r, x - STATE_GAP, Glyph::Check, palette().ok)
        }
        DlState::Failed(why) => {
            let why = fit::truncate_to(why, r.w / 3, |s| measure_ttf(s, PX));
            let x = right_text(fb, r, x, &why, palette().muted);
            right_glyph(fb, r, x - STATE_GAP, Glyph::Close, palette().err)
        }
    };
    let below = format!("{} \u{b7} {}", host_of(&d.url), human_bytes(d.bytes));
    rows::lines(fb, r, x, &d.name, &below);
}

/* What the tile of a file named `name` says: its extension in capitals,
 * at most four letters, or `FILE` when it has none. */
fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => {
            ext.chars().take(4).collect::<String>().to_ascii_uppercase()
        }
        _ => String::from("FILE"),
    }
}
