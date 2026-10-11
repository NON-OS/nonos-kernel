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

use crate::browser::paint::tokens;
use crate::browser::paint::toolbar::{buttons, pill as field};
use crate::browser::state::State;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::toolbar_geom::{self, ToolbarGeom};

/* The toolbar: a white strip with a hairline under it, Back and Forward
 * (dimmed when there is nowhere to go), Reload (Stop while a page loads),
 * Home, the address pill with its route badge, and the menu. */
pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.fill_rect(0, 0, fb.width, fb.height, tokens::SURFACE);
    fb.fill_rect(0, fb.height.saturating_sub(1), fb.width, 1, tokens::EDGE);
    let g = geom(fb);
    buttons::paint(state, &g, fb);
    field::paint(state, &g, fb);
}

/* The address pill alone: it repaints on its own for every keystroke, so
 * typing redraws this and nothing else. */
pub fn pill(state: &State, fb: &mut PaintBuffer) {
    let g = geom(fb);
    field::paint(state, &g, fb);
}

fn geom(fb: &PaintBuffer) -> ToolbarGeom {
    toolbar_geom::buttons(Rect::new(0, 0, fb.width as i32, fb.height as i32))
}
