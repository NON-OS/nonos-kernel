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
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::left;
use nonos_toolkit::widgets::{NavItem, Rect, Separator};

use crate::about::data::build::VERSION;
use crate::about::data::product::NAME;
use crate::about::format::trimmed;
use crate::about::section::SECTIONS;
use crate::about::state::State;

use super::hover::look;
use super::metrics::{BODY_PX, NAV_PAD_X, SIDEBAR_W, SIDE_FOOT_H, SIDE_FOOT_LINE, SIDE_FOOT_TOP};
use super::mono::{mono, valid};
use super::nav_geom::{rect, row_w, row_x};

/// The sidebar down the window's left side, `h` tall: a shared entry per
/// section in the box `nav_geom` gives it, each drawing the pointer's hover.
pub fn paint(fb: &mut PaintBuffer, state: &State, h: u32) {
    let r = roles();
    fb.fill_rect(0, 0, SIDEBAR_W, h, r.sunken.argb());
    fb.fill_rect(SIDEBAR_W - 1, 0, 1, h, r.border.argb());
    for (i, section) in SECTIONS.iter().enumerate() {
        let item = NavItem::new(valid(section.nav_label())).icon(section.icon());
        let look = look(&state.pointer, state.hover, *section);
        item.active(*section == state.section).state(look).draw(fb, rect(i));
    }
    paint_foot(fb, h);
}

// The footer mark is the window's provenance in two lines: which system this is
// and which image of it, taken from the same VERSION file the build embeds.
fn paint_foot(fb: &mut PaintBuffer, h: u32) {
    let r = roles();
    let y = h.saturating_sub(SIDE_FOOT_H);
    Separator::new().draw(fb, Rect { x: row_x(), y, w: row_w(), h: 1 });
    let x = row_x() + NAV_PAD_X;
    left(fb, x, (y + SIDE_FOOT_TOP) as i32, valid(NAME), r.accent, BODY_PX);
    let line = (y + SIDE_FOOT_TOP + SIDE_FOOT_LINE) as i32;
    let advance = left(fb, x, line, "v", r.muted, BODY_PX);
    mono(fb, advance.max(0) as u32, line, trimmed(VERSION), r.muted, BODY_PX);
}
