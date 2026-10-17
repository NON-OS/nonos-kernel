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

//! Where a checkbox or radio places its square mark at the left, with
//! its label to the right, both centred vertically.

use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CHECK, SPACE};
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;
use crate::widgets::rect::centre;
use crate::widgets::text;

/// A mark and its label placed in a box, in drawing pixels.
pub(crate) struct Marked {
    pub(crate) body: Rect,
    pub(crate) mark: Rect,
    pub(crate) label: Rect,
    pub(crate) label_top: i32,
    pub(crate) px: f32,
}

/// The body text size a label is drawn at.
fn px() -> f32 {
    scale().font(TextRole::Body.px())
}

/// The mark's side, then `SPACE.sm` and the label's width when there is a
/// label, by the taller of the mark and the label's line.
pub(crate) fn size(label: &str) -> (u32, u32) {
    let side = scale().px(CHECK);
    if label.is_empty() {
        return (side, side);
    }
    let (px, gap) = (px(), scale().px(u32::from(SPACE.sm)));
    let lh = line_height(px).max(0) as u32;
    (side.saturating_add(gap).saturating_add(text::width(label, px)), side.max(lh))
}

/// The body is the size clamped to `at`, at its left edge and centred
/// vertically in it. The mark is a square at the body's left, centred
/// vertically, and the label box takes what is left after `SPACE.sm`.
pub(crate) fn place(label: &str, at: Rect) -> Marked {
    let (w, h) = size(label);
    let body = Rect { x: at.x, ..centre(at, w, h) };
    let side = scale().px(CHECK).min(body.w).min(body.h);
    let mark = Rect { x: body.x, ..centre(body, side, side) };
    let used = side.saturating_add(scale().px(u32::from(SPACE.sm)));
    let label = Rect { x: body.x.saturating_add(used), w: body.w.saturating_sub(used), ..body };
    let px = px();
    Marked { body, mark, label, label_top: text::centre_top(body.y, body.h, px), px }
}
