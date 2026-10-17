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

//! Painting a mark and its label in the states every widget shares.

use super::Marked;
use crate::design::scale::scale;
use crate::theme::{roles, Opaque};
use crate::widgets::{draw, text, State, Surface};

/// Paints the mark, the hover wash, the outline, what `inner` draws when
/// `on`, the label and the focus ring, the mark rounded at `radius`. On
/// fills the mark with `accent` and hands `inner` the `on_accent` ink; off
/// outlines it in `border_strong` over the ground, and pressed gives it a
/// `surface` fill moved away from the outline. Disabled outlines the mark
/// and draws `inner` and the label in `disabled`, and ignores the other
/// states.
pub(crate) fn paint<S: Surface>(
    fb: &mut S,
    p: &Marked,
    radius: u32,
    on: bool,
    label: &str,
    st: State,
    inner: impl FnOnce(&mut S, Opaque),
) {
    let (r, s, live) = (roles(), scale(), !st.disabled);
    let (fill, edge, ink) = if !live {
        (None, Some(r.disabled), r.disabled)
    } else if on {
        (Some(r.accent), None, r.on_accent)
    } else {
        (None, Some(r.border_strong), r.border_strong)
    };
    let fill =
        if live && st.pressed { Some(draw::pressed(fill.unwrap_or(r.surface), ink)) } else { fill };
    if let Some(c) = fill {
        draw::round(fb, p.mark, radius, c);
    }
    if live && st.hovered {
        draw::round(fb, p.mark, radius, r.hover_wash);
    }
    if let Some(c) = edge {
        draw::outline(fb, p.mark, radius, s.hair(), c);
    }
    if on {
        inner(fb, ink);
    }
    let text_ink = if live { r.text } else { r.disabled };
    let cut = text::truncate(label, p.label.w, p.px);
    text::left(fb, p.label.x, p.label_top, &cut, text_ink, p.px);
    if live && st.focused {
        draw::outline(fb, p.mark, radius, s.hair().saturating_mul(2), r.focus_ring);
    }
}
