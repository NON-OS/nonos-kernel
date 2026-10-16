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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::widgets::{Button, Kind, Rect as Area};

use crate::ui::layout::Rect;

pub type Glyph = fn(&mut PaintBuffer, u32, u32, u32, u32);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Primary,
}

fn kind(tone: Tone) -> Kind {
    match tone {
        Tone::Primary => Kind::Primary,
    }
}

pub fn paint_button(fb: &mut PaintBuffer, r: Rect, label: &str, tone: Tone) {
    Button::new(label).kind(kind(tone)).draw(fb, Area { x: r.x, y: r.y, w: r.w, h: r.h });
}
