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

use crate::browser::paint::sidebar::{brand, group_row, row};
use crate::browser::paint::tokens;
use crate::browser::shell::cards::members;
use crate::browser::shell::Shell;
use crate::browser::ui::layout::Layout;
use crate::browser::ui::sidebar_geom::{self, RowKind};

const DIVIDER_PAD: i32 = 12;

/// The sidebar: its fill and right edge, the brand row in full mode, the
/// two divider hairlines, every row and the Tab Groups section, the row
/// standing for what the window shows lit. `on` is that row, if any.
pub fn paint(shell: &Shell, on: Option<RowKind>, lay: &Layout, fb: &mut PaintBuffer) {
    let s = lay.sidebar;
    if s.w <= 0 || s.h <= 0 {
        return;
    }
    fb.fill_rect(s.x as u32, s.y as u32, s.w as u32, s.h as u32, tokens::SIDEBAR);
    fb.fill_rect((s.right() - 1) as u32, s.y as u32, 1, s.h as u32, tokens::EDGE);
    brand::paint(sidebar_geom::brand(lay.rail, s), fb);
    let dw = (s.w - 2 * DIVIDER_PAD - 1).max(0) as u32;
    let n = shell.groups.len();
    for y in sidebar_geom::dividers(lay.rail, s, n) {
        fb.fill_rect((s.x + DIVIDER_PAD) as u32, y.max(0) as u32, dw, 1, tokens::EDGE);
    }
    if let Some(h) = sidebar_geom::groups_head(lay.rail, s, n) {
        group_row::heading(fb, h);
    }
    let members = members(shell);
    for r in sidebar_geom::rows(lay.rail, s, n).iter() {
        let lit = on == Some(r.kind);
        match r.kind {
            RowKind::Group(i) => {
                if let Some(g) = shell.groups.get(i) {
                    group_row::paint(fb, r, g, lit, &members);
                }
            }
            RowKind::NewGroup => group_row::new_group(fb, r.rect, n),
            _ => row::paint(fb, r, lay.rail, lit, members.len()),
        }
    }
}
