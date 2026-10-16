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
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use super::metrics::{PX_BODY, RADIUS_BTN};
use super::rect::Rect;
use super::text;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Primary,
    Ghost,
    Danger,
    Disabled,
}

impl Style {
    fn colours(self) -> (u32, u32, u32) {
        let r = roles();
        let (raised, edge, danger) = (r.raised.argb(), r.border_strong.argb(), r.danger.argb());
        match self {
            Style::Primary => (r.accent_wash.argb(), r.accent_edge.argb(), r.accent.argb()),
            Style::Ghost => (raised, edge, r.text_2.argb()),
            Style::Danger => (with_alpha(danger, 0x22), danger, danger),
            Style::Disabled => (raised, edge, r.disabled.argb()),
        }
    }
}

// The label is centred on the measured advance and on the line box, so the
// text sits where the rect says it does at every type size.
pub fn paint(fb: &mut PaintBuffer, r: Rect, label: &[u8], style: Style, hover: bool) {
    let (bg, border, ink) = style.colours();
    let radius = RADIUS_BTN.min(r.3 / 2);
    fb.fill_round(r.0, r.1, r.2, r.3, radius, bg);
    if hover && style != Style::Disabled {
        fb.fill_round(r.0, r.1, r.2, r.3, radius, roles().hover_wash.argb());
    }
    fb.stroke_round(r.0, r.1, r.2, r.3, radius, 1, border);
    let cut = text::fit(label, PX_BODY, r.2);
    let x = r.0 + r.2.saturating_sub(text::width_of(cut, PX_BODY)) / 2;
    text::left(fb, x, text::centred_top(r.1, r.3, PX_BODY), cut, ink, PX_BODY);
}
