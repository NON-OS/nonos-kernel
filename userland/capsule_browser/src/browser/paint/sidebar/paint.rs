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

use crate::browser::paint::sidebar::{brand, row};
use crate::browser::paint::tokens;
use crate::browser::ui::layout::Layout;
use crate::browser::ui::sidebar_geom::{self, RowKind};

const DIVIDER_PAD: i32 = 12;

/// The sidebar: its fill and right edge, the brand row in full mode, the
/// hairline over Settings and every row, the one standing for what the
/// window shows lit. `on` is that row, if any.
pub fn paint(on: Option<RowKind>, lay: &Layout, fb: &mut PaintBuffer) {
    let s = lay.sidebar;
    if s.w <= 0 || s.h <= 0 {
        return;
    }
    fb.fill_rect(s.x as u32, s.y as u32, s.w as u32, s.h as u32, tokens::SIDEBAR);
    fb.fill_rect((s.right() - 1) as u32, s.y as u32, 1, s.h as u32, tokens::EDGE);
    brand::paint(sidebar_geom::brand(lay.rail, s), fb);
    let dw = (s.w - 2 * DIVIDER_PAD - 1).max(0) as u32;
    let y = sidebar_geom::divider(lay.rail, s).max(0) as u32;
    fb.fill_rect((s.x + DIVIDER_PAD) as u32, y, dw, 1, tokens::EDGE);
    for r in sidebar_geom::rows(lay.rail, s).iter() {
        row::paint(fb, r, lay.rail, on == Some(r.kind));
    }
}
