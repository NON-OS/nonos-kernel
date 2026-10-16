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
use nonos_toolkit::widgets::{NavItem, Rect};

use crate::settings::section::{Section, SECTIONS};
use crate::settings::section_text::nav;

use super::icon_table::icon;
use super::metrics::{NAV_H, SIDEBAR_W};
use super::nav_geom::{row_w, row_x, row_y};

pub fn paint(fb: &mut PaintBuffer, active: Section, h: u32) {
    let r = roles();
    fb.fill_rect(0, 0, SIDEBAR_W, h, r.sunken.argb());
    fb.fill_rect(SIDEBAR_W - 1, 0, 1, h, r.border.argb());
    for (i, section) in SECTIONS.iter().enumerate() {
        paint_row(fb, *section, row_y(i), *section == active);
    }
}

/// One entry: the toolkit item over the whole row box, drawing its own icon
/// and label inside it, so the active wash covers both.
fn paint_row(fb: &mut PaintBuffer, section: Section, y: u32, active: bool) {
    let at = Rect { x: row_x(), y, w: row_w(), h: NAV_H };
    NavItem::new(nav(section)).icon(icon(section)).active(active).draw(fb, at);
}
