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

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::pages::pills::{PAD, PX};
use crate::browser::paint::tokens::palette;
use crate::browser::shell::kept::Group;
use crate::browser::shell::{groups, Page, Shell};
use crate::browser::ui::list_geom::{ListGeom, PILL_H};
use crate::browser::ui::rect::Rect;

pub const TITLE_PX: f32 = 34.0;
const FIELD_MIN: i32 = 320;
const FIELD_PAD: i32 = 8;
const CARET_W: u32 = 2;
const DELETE: &str = "Delete group";

/// The group the Tabs page is filtered to, if it is.
pub fn filtered(shell: &Shell) -> Option<&Group> {
    let id = shell.group_filter.filter(|_| shell.page == Page::Tabs)?;
    groups::find(&shell.groups, id)
}

/// The group's name, which takes a click to rename; while renaming, the
/// field around the name being typed.
pub fn name_rect(g: &ListGeom, shell: &Shell, gr: &Group) -> Rect {
    let lh = line_height(TITLE_PX);
    match shell.rename.as_deref() {
        Some(t) => {
            let w = (measure_ttf(t, TITLE_PX) + 2 * FIELD_PAD).max(FIELD_MIN);
            Rect::new(g.frame.x - FIELD_PAD, g.title_y - FIELD_PAD, w, lh + 2 * FIELD_PAD)
        }
        None => Rect::new(g.frame.x, g.title_y, measure_ttf(&gr.name, TITLE_PX), lh),
    }
}

/// The Delete group button, at the right end of the pill row.
pub fn delete_rect(g: &ListGeom) -> Rect {
    let w = measure_ttf(DELETE, PX) + 2 * PAD;
    Rect::new(g.frame.right() - w, g.pills_y, w, PILL_H)
}

/// The header of the Tabs page filtered to `gr`: its name or the rename
/// field, a line saying how many tabs it holds, and Delete group.
pub fn paint(shell: &Shell, gr: &Group, tabs: usize, g: &ListGeom, fb: &mut PaintBuffer) {
    let n = name_rect(g, shell, gr);
    if let Some(t) = shell.rename.as_deref() {
        let (x, y, w, h) = (n.x as u32, n.y as u32, n.w as u32, n.h as u32);
        fb.fill_round(x, y, w, h, FIELD_PAD as u32, palette().surface);
        fb.stroke_round(x, y, w, h, FIELD_PAD as u32, 2, palette().accent);
        fb.text_ttf(g.frame.x, g.title_y, t, palette().ink, TITLE_PX);
        let cx = g.frame.x + measure_ttf(t, TITLE_PX) + 1;
        fb.fill_rect(
            cx as u32,
            g.title_y as u32,
            CARET_W,
            line_height(TITLE_PX) as u32,
            palette().accent,
        );
    } else {
        fb.text_ttf(g.frame.x, g.title_y, &gr.name, palette().ink, TITLE_PX);
    }
    let sub = format!("{} open in this group. Click the name to rename it", tabs);
    fb.text_ttf(g.frame.x, g.sub_y, &sub, palette().muted, PX);
    let d = delete_rect(g);
    let (x, y, w, h) = (d.x as u32, d.y as u32, d.w as u32, d.h as u32);
    fb.fill_round(x, y, w, h, (d.h / 2) as u32, palette().surface);
    fb.stroke_round(x, y, w, h, (d.h / 2) as u32, 1, palette().edge);
    fb.text_ttf(d.x + PAD, d.y + (d.h - line_height(PX)) / 2, DELETE, palette().err, PX);
}
