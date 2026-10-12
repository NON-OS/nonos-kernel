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

use alloc::string::String;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::clip;
use crate::browser::paint::tokens::{self, palette};
use crate::browser::shell::groups;
use crate::browser::shell::Shell;
use crate::browser::ui::fit;
use crate::browser::ui::grid_geom::chip_rect;
use crate::browser::ui::rect::Rect;

const PX: f32 = 17.0;
const PAD: i32 = 12;

/// What the chip of a tab in `group` says, and the group's colour; None
/// for no group.
fn look(shell: &Shell, group: Option<u8>) -> (String, Option<u32>) {
    match group.and_then(|id| groups::find(&shell.groups, id)) {
        Some(g) => (g.name.clone(), Some(tokens::TILES[g.color as usize % tokens::TILES.len()])),
        None => (String::from("No group"), None),
    }
}

/// Where the chip of a tab in `group` sits on its card `card`. Painter and
/// click share it.
pub fn rect(card: Rect, shell: &Shell, group: Option<u8>) -> Rect {
    chip_rect(card, measure_ttf(&look(shell, group).0, PX) + 2 * PAD)
}

/// The chip: the group's colour with white ink, or a muted fill reading
/// "No group".
pub fn paint(fb: &mut PaintBuffer, card: Rect, shell: &Shell, group: Option<u8>) {
    let (label, tint) = look(shell, group);
    let r = rect(card, shell, group);
    let radius = (r.h / 2) as u32;
    let ink = match tint {
        Some(c) => {
            clip::round(fb, r, radius, c);
            tokens::TILE_INK
        }
        None => {
            clip::round(fb, r, radius, palette().field);
            palette().muted
        }
    };
    let text = fit::truncate_to(&label, r.w - 2 * PAD, |t| measure_ttf(t, PX));
    fb.text_ttf(r.x + PAD, r.y + (r.h - line_height(PX)) / 2, &text, ink, PX);
}
