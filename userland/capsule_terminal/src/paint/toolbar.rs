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
use nonos_toolkit::theme::Roles;

use super::tab_pill::{PILL_H, RADIUS};
use super::tool_icon::{icon_new_tab, icon_search, icon_theme};
use crate::layout::Rect;

pub const TOOL_W: u32 = 30;
/// Buttons on the strip. Every one of them does something.
///
/// There were five. Two were controls for things that do not exist: a split
/// button for panes the terminal has never had, and a settings button with
/// nothing behind it. They were drawn dimmed and refused clicks, which is the
/// polite version of the problem and still leaves a reader wondering what they
/// did wrong. A control that can never activate is not a disabled control, it
/// is a promise the window cannot keep, so they are gone rather than greyed.
pub const TOOL_COUNT: usize = 3;
pub const TOOLBAR_W: u32 = TOOL_W * TOOL_COUNT as u32;

const ICON: u32 = 16;

/// Shared geometry for one toolbar button; the painter and the hit-test both
/// read their bounds from here so a click can never drift from the glyph.
pub fn button_rect(i: usize, avail_w: u32) -> Rect {
    let base = avail_w.saturating_sub(TOOLBAR_W);
    Rect { x: base + i as u32 * TOOL_W, y: 0, w: TOOL_W, h: PILL_H }
}

fn icon_rect(r: Rect) -> Rect {
    Rect { x: r.x + (r.w - ICON) / 2, y: r.y + (r.h - ICON) / 2, w: ICON, h: ICON }
}

pub fn draw_toolbar(fb: &mut PaintBuffer, avail_w: u32, active: Option<usize>, c: &Roles) {
    for i in 0..TOOL_COUNT {
        let r = button_rect(i, avail_w);
        if r.x + r.w > fb.width {
            continue;
        }
        let hot = active == Some(i);
        let fg = if hot { c.accent_text } else { c.muted }.argb();
        if hot {
            fb.fill_round(r.x + 1, r.y, r.w - 2, r.h, RADIUS, c.hover_wash.argb());
        }
        let ic = icon_rect(r);
        match i {
            0 => icon_new_tab(fb, ic, fg),
            1 => icon_search(fb, ic, fg),
            _ => icon_theme(fb, ic, fg),
        }
    }
}

/// Index of the button under `(x, y)`.
pub fn toolbar_hit(avail_w: u32, x: u32, y: u32) -> Option<usize> {
    (0..TOOL_COUNT).find(|&i| {
        let r = button_rect(i, avail_w);
        x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h
    })
}
