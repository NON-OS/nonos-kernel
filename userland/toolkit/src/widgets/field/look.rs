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

//! The colours and edge a field draws with, by state.

use super::Field;
use crate::design::scale::scale;
use crate::theme::{roles, Opaque, Translucent};

/// A field's body fill, hover wash, edge colour and width, and ink.
pub(super) struct Look {
    pub(super) fill: Opaque,
    pub(super) wash: Option<Translucent>,
    pub(super) edge: Opaque,
    pub(super) edge_w: u32,
    pub(super) ink: Opaque,
}

impl Field<'_> {
    /// A `raised` body with a hairline `border_strong` edge. Focused swaps
    /// the edge for `accent` at two hairlines, which is the focus mark;
    /// hovered and not focused adds `hover_wash`. Text inks in `text`, the
    /// placeholder in `quiet`. Disabled draws edge and ink in `disabled` and
    /// ignores the other states.
    pub(super) fn look(&self) -> Look {
        let (r, hair, st) = (roles(), scale().hair(), self.state);
        let ink = if self.text.is_empty() { r.quiet } else { r.text };
        let look = |wash, edge, edge_w, ink| Look { fill: r.raised, wash, edge, edge_w, ink };
        if st.disabled {
            return look(None, r.disabled, hair, r.disabled);
        }
        if st.focused {
            return look(None, r.accent, hair.saturating_mul(2), ink);
        }
        let wash = st.hovered.then_some(r.hover_wash);
        look(wash, r.border_strong, hair, ink)
    }
}
