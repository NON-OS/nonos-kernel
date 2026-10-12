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
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::pages::group_head::{self, TITLE_PX};
use crate::browser::paint::pages::pills::{
    self, Pill, BADGE_GAP, BADGE_PAD, DOT, DOT_GAP, PAD, PX,
};
use crate::browser::paint::tokens::palette;
use crate::browser::shell::{Page, Shell};
use crate::browser::ui::list_geom::{ListGeom, BAND_H};
use crate::browser::ui::rect::Rect;

const BADGE_INSET: i32 = 5;

/// The header band over a list page: it covers the rows scrolled under it,
/// then carries the page title, a muted line under it and the filter pills.
pub fn paint(shell: &Shell, tabs: usize, g: &ListGeom, fb: &mut PaintBuffer) {
    fb.fill_rect(0, 0, fb.width, BAND_H as u32, palette().ground);
    match group_head::filtered(shell) {
        Some(gr) => group_head::paint(shell, gr, tabs, g, fb),
        None => {
            let (title, sub) = heading(shell, tabs);
            fb.text_ttf(g.frame.x, g.title_y, title, palette().ink, TITLE_PX);
            fb.text_ttf(g.frame.x, g.sub_y, &sub, palette().muted, PX);
        }
    }
    let (specs, widths) = pills::row(shell, g);
    for (i, p) in specs.iter().enumerate() {
        pill(fb, g.pill(&widths, i), p);
    }
}

fn heading(shell: &Shell, tabs: usize) -> (&'static str, String) {
    match shell.page {
        Page::Tabs => ("Tabs", format!("{} open in this window", tabs)),
        Page::Bookmarks => ("Bookmarks", format!("{} saved", shell.bookmarks.len())),
        Page::Downloads => ("Downloads", String::from("Saved files go to /home/Downloads")),
        _ => ("History", String::from("Pages visited this session. History clears at shutdown")),
    }
}

fn pill(fb: &mut PaintBuffer, r: Rect, p: &Pill) {
    let (fill, ink, badge, badge_ink) = match p.on {
        true => (palette().accent, palette().on_accent, palette().accent_soft, palette().accent),
        false => (palette().surface, palette().ink2, palette().field, palette().muted),
    };
    let (x, y, w, h, rad) = (r.x as u32, r.y as u32, r.w as u32, r.h as u32, (r.h / 2) as u32);
    fb.fill_round(x, y, w, h, rad, fill);
    if !p.on {
        fb.stroke_round(x, y, w, h, rad, 1, palette().edge);
    }
    let ink = if p.dim { palette().disabled } else { ink };
    let ty = r.y + (r.h - line_height(PX)) / 2;
    let tx = match p.dot {
        Some(tint) => {
            let (dx, dy) = ((r.x + PAD) as u32, (r.y + (r.h - DOT) / 2) as u32);
            fb.fill_round(dx, dy, DOT as u32, DOT as u32, (DOT / 2) as u32, tint);
            r.x + PAD + DOT + DOT_GAP
        }
        None => r.x + PAD,
    };
    fb.text_ttf(tx, ty, &p.label, ink, PX);
    let Some(n) = p.count else {
        return;
    };
    let bx = tx + measure_ttf(&p.label, PX) + BADGE_GAP;
    let bh = r.h - 2 * BADGE_INSET;
    let (bw, by) = (pills::badge_w(n), r.y + BADGE_INSET);
    fb.fill_round(bx as u32, by as u32, bw as u32, bh as u32, (bh / 2) as u32, badge);
    fb.text_ttf(bx + BADGE_PAD, ty, &format!("{}", n), badge_ink, PX);
}
