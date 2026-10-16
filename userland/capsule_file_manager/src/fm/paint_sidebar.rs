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

use super::layout::SIDEBAR_W;
use super::sidebar_brand::paint_brand;
use super::sidebar_model::SideKind;
use super::sidebar_row_paint::{nav_row, rule, section_label};
use super::sidebar_rows::side_rows;
use super::sidebar_storage::paint_storage;
use super::state::State;

// Fixed quick-access locations. `(display, path)`; paths match how the vfs
// reports directory prefixes.
pub const PLACES: [(&str, &str); 3] =
    [("Root", "/"), ("Documents", "/docs/"), ("Capsules", "/capsules/")];

/// Draws the rail from the one layout pass `side_hit` also reads, so every mark
/// on screen has a slot behind it and no slot is left undrawn.
pub fn paint_sidebar(state: &State, fb: &mut PaintBuffer) {
    let (h, r) = (fb.height, roles());
    fb.fill_rect(0, 0, SIDEBAR_W, h, r.sunken.argb());
    fb.fill_rect(SIDEBAR_W - 1, 0, 1, h, r.border.argb());
    paint_brand(fb);
    for row in side_rows(state) {
        match row.kind {
            SideKind::Label => section_label(fb, &row.label, row.y, row.h),
            SideKind::Rule => rule(fb, row.y, row.h),
            SideKind::Nav => nav_row(state, fb, &row),
            SideKind::Storage => paint_storage(state, fb, row.y),
        }
    }
}
